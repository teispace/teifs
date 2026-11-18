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
