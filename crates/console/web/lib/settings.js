// A bucket's settings, as S3's subresources hold them: versioning, default encryption,
// tags, policy and lifecycle. Parsers and documents here; the calls at the end.

import { ApiError, request, xml } from "./api.js";
import { path } from "./s3.js";
import { build, child, children, escape, parse, text } from "./xml.js";

/** `GetBucketVersioning`: `Enabled`, `Suspended`, or "" (never enabled). */
export function parseVersioning(root) {
  return text(root, "Status");
}

/** `GetBucketEncryption`'s first rule: `{ algorithm, keyId, bucketKey }`. */
export function parseEncryption(root) {
  const rule = child(root, "Rule");
  const sse = child(rule, "ApplyServerSideEncryptionByDefault");
  return {
    algorithm: text(sse, "SSEAlgorithm"),
    keyId: text(sse, "KMSMasterKeyID"),
    bucketKey: text(rule, "BucketKeyEnabled") === "true",
  };
}

/** The `ServerSideEncryptionConfiguration` for `algorithm` (`AES256`, `aws:kms`, `aws:kms:dsse`). */
export function encryptionXml({ algorithm, keyId, bucketKey }) {
  const kms = algorithm.startsWith("aws:kms");
  return build([
    "ServerSideEncryptionConfiguration",
    [
      "Rule",
      ["ApplyServerSideEncryptionByDefault", ["SSEAlgorithm", algorithm], kms && keyId ? ["KMSMasterKeyID", keyId] : null],
      kms ? ["BucketKeyEnabled", bucketKey ? "true" : "false"] : null,
    ],
  ]);
}

/** `GetBucketTagging`: `[{ key, value }]`. */
export function parseTags(root) {
  return children(child(root, "TagSet"), "Tag").map((t) => ({ key: text(t, "Key"), value: text(t, "Value") }));
}

/** Why `tags` can't be a bucket's tags (S3's limits), or "". */
export function tagsProblem(tags) {
  if (tags.length > 50) return "A bucket has at most 50 tags.";
  const seen = new Set();
  for (const { key, value } of tags) {
    if (!key) return "Every tag needs a key.";
    if ([...key].length > 128) return `The key ${key} is longer than 128 characters.`;
    if ([...value].length > 256) return `The value of ${key} is longer than 256 characters.`;
    if (key.toLowerCase().startsWith("aws:")) return "Keys starting with aws: are reserved.";
    if (seen.has(key)) return `The key ${key} is there twice.`;
    seen.add(key);
  }
  return "";
}

/** The `Tagging` document for `tags`. */
export function taggingXml(tags) {
  return build(["Tagging", ["TagSet", ...tags.map((t) => ["Tag", ["Key", t.key], ["Value", t.value]])]]);
}

/** A policy's JSON indented for reading, or as it came when it isn't JSON. */
export function prettyPolicy(policy) {
  try {
    return JSON.stringify(JSON.parse(policy), null, 2);
  } catch {
    return policy;
  }
}

/** Why `policy` can't be a bucket policy before the server even looks, or "". */
export function policyProblem(policy) {
  let parsed;
  try {
    parsed = JSON.parse(policy);
  } catch (e) {
    return `The policy isn't JSON: ${e.message}`;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "A policy is a JSON object.";
  if (!parsed.Statement) return "A policy needs a Statement.";
  return "";
}

/** A summary of each lifecycle rule: `{ id, status, prefix, expirationDays, noncurrentDays, abortDays }`. */
export function parseLifecycle(root) {
  return children(root, "Rule").map((r) => {
    const filter = child(r, "Filter");
    const prefix = text(r, "Prefix") || text(filter, "Prefix") || text(child(filter, "And"), "Prefix");
    return {
      id: text(r, "ID"),
      status: text(r, "Status"),
      prefix,
      expirationDays: text(child(r, "Expiration"), "Days"),
      noncurrentDays: text(child(r, "NoncurrentVersionExpiration"), "NoncurrentDays"),
      abortDays: text(child(r, "AbortIncompleteMultipartUpload"), "DaysAfterInitiation"),
    };
  });
}

/** A lifecycle `Rule`'s XML: objects under `prefix` expire after `days`, old versions after `noncurrentDays`. */
export function expirationRule({ id, prefix = "", days, noncurrentDays, abortDays }) {
  const parts = [
    `<ID>${escape(id)}</ID>`,
    `<Filter><Prefix>${escape(prefix)}</Prefix></Filter>`,
    "<Status>Enabled</Status>",
    days ? `<Expiration><Days>${Number(days)}</Days></Expiration>` : "",
    noncurrentDays ? `<NoncurrentVersionExpiration><NoncurrentDays>${Number(noncurrentDays)}</NoncurrentDays></NoncurrentVersionExpiration>` : "",
    abortDays ? `<AbortIncompleteMultipartUpload><DaysAfterInitiation>${Number(abortDays)}</DaysAfterInitiation></AbortIncompleteMultipartUpload>` : "",
  ];
  return `<Rule>${parts.join("")}</Rule>`;
}

const EMPTY_LIFECYCLE = '<?xml version="1.0" encoding="UTF-8"?>\n<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n</LifecycleConfiguration>';

/** `document` (a `LifecycleConfiguration`, or "" for none) with `rule` added. */
export function addRule(document, rule) {
  const base = document.trim() ? document : EMPTY_LIFECYCLE;
  const end = base.lastIndexOf("</LifecycleConfiguration>");
  if (end < 0) throw new Error("That isn't a LifecycleConfiguration.");
  return `${base.slice(0, end)}  ${rule}\n${base.slice(end)}`;
}

/** Why `document` can't be sent as a lifecycle configuration, or "". */
export function lifecycleProblem(document) {
  try {
    const root = parse(document);
    if (root.name !== "LifecycleConfiguration") return "The document's root is LifecycleConfiguration.";
    if (!children(root, "Rule").length) return "Add a rule, or delete the configuration.";
  } catch (e) {
    return `The document isn't XML: ${e.message}`;
  }
  return "";
}

/** A subresource's document, or `null` when the bucket has none (`codes` say so). */
async function optional(call, codes) {
  try {
    return await call();
  } catch (e) {
    if (e instanceof ApiError && codes.includes(e.code)) return null;
    throw e;
  }
}

export const bucket = {
  versioning: async (name) => parseVersioning(await xml("GET", path(name), { query: { versioning: "" } })),
  setVersioning: (name, status) =>
    request("PUT", path(name), {
      query: { versioning: "" },
      headers: { "content-type": "application/xml" },
      body: build(["VersioningConfiguration", ["Status", status]]),
    }),
  encryption: async (name) => {
    const root = await optional(() => xml("GET", path(name), { query: { encryption: "" } }), ["ServerSideEncryptionConfigurationNotFoundError"]);
    return root ? parseEncryption(root) : null;
  },
  setEncryption: (name, settings) =>
    request("PUT", path(name), { query: { encryption: "" }, headers: { "content-type": "application/xml" }, body: encryptionXml(settings) }),
  tags: async (name) => {
    const root = await optional(() => xml("GET", path(name), { query: { tagging: "" } }), ["NoSuchTagSet"]);
    return root ? parseTags(root) : [];
  },
  setTags: (name, tags) =>
    tags.length
      ? request("PUT", path(name), { query: { tagging: "" }, headers: { "content-type": "application/xml" }, body: taggingXml(tags) })
      : request("DELETE", path(name), { query: { tagging: "" } }),
  policy: async (name) => {
    const response = await optional(() => request("GET", path(name), { query: { policy: "" } }), ["NoSuchBucketPolicy"]);
    return response ? response.text() : "";
  },
  setPolicy: (name, policy) =>
    policy.trim()
      ? request("PUT", path(name), { query: { policy: "" }, headers: { "content-type": "application/json" }, body: policy })
      : request("DELETE", path(name), { query: { policy: "" } }),
  lifecycle: async (name) => {
    const response = await optional(() => request("GET", path(name), { query: { lifecycle: "" } }), ["NoSuchLifecycleConfiguration"]);
    return response ? response.text() : "";
  },
  setLifecycle: (name, document) =>
    document.trim()
      ? request("PUT", path(name), { query: { lifecycle: "" }, headers: { "content-type": "application/xml" }, body: document })
      : request("DELETE", path(name), { query: { lifecycle: "" } }),
};
