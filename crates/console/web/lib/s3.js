// S3's calls, as the console makes them: paths under /api/s3/, answers parsed into plain
// objects. Parsers are separate from the calls so they're tested without a server.

import { build, child, children, text } from "./xml.js";
import { request, xml } from "./api.js";

/** A key (or bucket) as a URL path: every byte but RFC 3986's unreserved and `/` encoded. */
export function encodeKey(key) {
  return Array.from(new TextEncoder().encode(key), (b) => {
    const c = String.fromCharCode(b);
    return /[A-Za-z0-9\-._~/]/.test(c) ? c : `%${b.toString(16).toUpperCase().padStart(2, "0")}`;
  }).join("");
}

/** The console's path for a bucket, or one of its objects. */
export function path(bucket, key) {
  return key === undefined ? `/api/s3/${encodeKey(bucket)}` : `/api/s3/${encodeKey(bucket)}/${encodeKey(key)}`;
}

/** Why `name` can't be a bucket's name (S3's general-purpose bucket rules), or "". */
export function bucketNameProblem(name) {
  if (name.length < 3 || name.length > 63) return "A bucket's name is 3 to 63 characters long.";
  if (!/^[a-z0-9.-]+$/.test(name)) return "Use only lowercase letters, digits, dots and hyphens.";
  if (!/^[a-z0-9]/.test(name) || !/[a-z0-9]$/.test(name)) return "Start and end the name with a letter or a digit.";
  if (name.includes("..")) return "Don't put two dots next to each other.";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name)) return "A bucket's name can't look like an IP address.";
  if (/^(xn--|sthree-|amzn-s3-demo-)/.test(name)) return "That prefix is reserved.";
  if (/(-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)$/.test(name)) return "That suffix is reserved.";
  return "";
}

/** `ListBuckets`'s answer: `{ buckets: [{ name, created, region }], owner }`. */
export function parseBuckets(root) {
  const list = child(root, "Buckets");
  return {
    owner: text(child(root, "Owner"), "DisplayName") || text(child(root, "Owner"), "ID"),
    buckets: children(list, "Bucket").map((b) => ({
      name: text(b, "Name"),
      created: text(b, "CreationDate"),
      region: text(b, "BucketRegion"),
    })),
    continuation: text(root, "ContinuationToken"),
  };
}

/** Every bucket the key may list. */
export async function listBuckets() {
  const all = [];
  let token;
  do {
    const page = parseBuckets(await xml("GET", "/api/s3/", { query: { "max-buckets": "1000", "continuation-token": token } }));
    all.push(...page.buckets);
    token = page.continuation || undefined;
  } while (token);
  return all.sort((a, b) => (a.name < b.name ? -1 : 1));
}

/** `CreateBucket`, optionally with Object Lock (which turns versioning on). */
export async function createBucket(name, { objectLock = false } = {}) {
  await request("PUT", path(name), {
    headers: objectLock ? { "x-amz-bucket-object-lock-enabled": "true" } : {},
  });
}

/** `DeleteBucket`: only an empty bucket goes. */
export async function deleteBucket(name) {
  await request("DELETE", path(name));
}

/** The `VersioningConfiguration` document for `status` (`Enabled` or `Suspended`). */
export function versioningXml(status) {
  return build(["VersioningConfiguration", ["Status", status]]);
}

/** `ListObjectsV2`'s answer: folders (common prefixes), objects and the next page's token. */
export function parseObjects(root) {
  return {
    prefixes: children(root, "CommonPrefixes").map((p) => text(p, "Prefix")),
    objects: children(root, "Contents").map((o) => ({
      key: text(o, "Key"),
      size: Number(text(o, "Size", "0")),
      modified: text(o, "LastModified"),
      etag: text(o, "ETag"),
      storageClass: text(o, "StorageClass"),
    })),
    next: text(root, "IsTruncated") === "true" ? text(root, "NextContinuationToken") : "",
  };
}

/** One page of what's under `prefix`, a folder at a time (`/` delimits). */
export async function listObjects(bucket, prefix, token, { delimiter = "/" } = {}) {
  return parseObjects(
    await xml("GET", path(bucket), {
      query: { "list-type": "2", prefix, delimiter: delimiter || undefined, "continuation-token": token || undefined, "max-keys": "1000" },
    }),
  );
}

/** `ListObjectVersions`' answer: versions and delete markers in S3's order, folders, next markers. */
export function parseVersions(root) {
  const entries = root.children
    .filter((c) => c.name === "Version" || c.name === "DeleteMarker")
    .map((v) => ({
      key: text(v, "Key"),
      versionId: text(v, "VersionId"),
      latest: text(v, "IsLatest") === "true",
      deleteMarker: v.name === "DeleteMarker",
      size: Number(text(v, "Size", "0")),
      modified: text(v, "LastModified"),
      etag: text(v, "ETag"),
    }));
  const truncated = text(root, "IsTruncated") === "true";
  return {
    prefixes: children(root, "CommonPrefixes").map((p) => text(p, "Prefix")),
    versions: entries,
    next: truncated ? { keyMarker: text(root, "NextKeyMarker"), versionIdMarker: text(root, "NextVersionIdMarker") } : null,
  };
}

/** One page of the versions under `prefix`, a folder at a time. */
export async function listVersions(bucket, prefix, next) {
  return parseVersions(
    await xml("GET", path(bucket), {
      query: {
        versions: "",
        prefix,
        delimiter: "/",
        "key-marker": next?.keyMarker || undefined,
        "version-id-marker": next?.versionIdMarker || undefined,
        "max-keys": "1000",
      },
    }),
  );
}

/** Every key under `prefix` (no delimiter), for deleting a folder. */
export async function allKeys(bucket, prefix) {
  const keys = [];
  let token = "";
  do {
    const page = await listObjects(bucket, prefix, token, { delimiter: "" });
    keys.push(...page.objects.map((o) => ({ key: o.key })));
    token = page.next;
  } while (token);
  return keys;
}

/** The `Delete` document for `DeleteObjects`: `[{ key, versionId? }]`, quietly. */
export function deleteXml(objects) {
  return build([
    "Delete",
    ["Quiet", "true"],
    ...objects.map((o) => ["Object", ["Key", o.key], o.versionId ? ["VersionId", o.versionId] : null]),
  ]);
}

/** `DeleteObjects`' failures: `[{ key, versionId, code, message }]`. */
export function parseDeleteErrors(root) {
  return children(root, "Error").map((e) => ({
    key: text(e, "Key"),
    versionId: text(e, "VersionId"),
    code: text(e, "Code"),
    message: text(e, "Message"),
  }));
}

/** Deletes `objects` (`[{ key, versionId? }]`), 1000 at a time; resolves with the failures. */
export async function deleteObjects(bucket, objects) {
  const failed = [];
  for (let i = 0; i < objects.length; i += 1000) {
    const root = await xml("POST", path(bucket), {
      query: { delete: "" },
      headers: { "content-type": "application/xml" },
      body: deleteXml(objects.slice(i, i + 1000)),
    });
    if (root) failed.push(...parseDeleteErrors(root));
  }
  return failed;
}

/** `DeleteObject`, of one version when `versionId` is given. */
export async function deleteObject(bucket, key, versionId) {
  await request("DELETE", path(bucket, key), { query: { versionId: versionId || undefined } });
}

/** An empty object whose key ends with `/`: what S3 consoles show as a folder. */
export async function createFolder(bucket, key) {
  await request("PUT", path(bucket, key.endsWith("/") ? key : `${key}/`), { body: "" });
}

/** The console's link that downloads an object (a version of it). */
export function downloadLink(bucket, key, versionId) {
  const version = versionId ? `?versionId=${encodeURIComponent(versionId)}` : "";
  return `/api/download/${encodeKey(bucket)}/${encodeKey(key)}${version}`;
}
