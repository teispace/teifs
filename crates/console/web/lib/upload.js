// Uploading files: one PUT for small files, a multipart upload for big ones (parts sent a
// few at a time, the upload aborted if one fails), as the AWS CLI does.

import { build, child, text } from "./xml.js";
import { ApiError, request, xml } from "./api.js";
import { path } from "./s3.js";

const MiB = 1024 * 1024;
/** Files up to this size go in one PUT. */
export const SINGLE_PUT_MAX = 16 * MiB;
/** The smallest part (S3 takes 5 MiB; bigger parts mean fewer requests). */
export const PART_SIZE = 16 * MiB;
/** S3's most parts in an upload. */
export const MAX_PARTS = 10000;
/** Parts sent at once. */
export const PARALLEL_PARTS = 4;

/**
 * How a file of `size` bytes is cut into parts: `[{ number, start, end }]` (end
 * exclusive), parts of `PART_SIZE`, or bigger whole MiBs when that would make more
 * than `MAX_PARTS`.
 */
export function planParts(size, partSize = PART_SIZE) {
  let part = partSize;
  if (Math.ceil(size / part) > MAX_PARTS) part = Math.ceil(size / MAX_PARTS / MiB) * MiB;
  const parts = [];
  for (let start = 0, number = 1; start < size || number === 1; start += part, number++) {
    parts.push({ number, start, end: Math.min(size, start + part) });
    if (size === 0) break;
  }
  return parts;
}

/** The `CompleteMultipartUpload` document for `parts` (`[{ number, etag }]`). */
export function completeXml(parts) {
  return build([
    "CompleteMultipartUpload",
    ...[...parts].sort((a, b) => a.number - b.number).map((p) => ["Part", ["PartNumber", String(p.number)], ["ETag", p.etag]]),
  ]);
}

/** The upload id in `CreateMultipartUpload`'s answer. */
export function parseUploadId(root) {
  return text(root, "UploadId") || text(child(root, "InitiateMultipartUploadResult"), "UploadId");
}

function contentType(file) {
  return file.type || "application/octet-stream";
}

/**
 * Uploads `file` as `key`; `progress(sent, total)` is called as parts finish, and
 * `signal` cancels it (aborting a multipart upload).
 */
export async function upload(bucket, key, file, { progress = () => {}, signal } = {}) {
  if (file.size <= SINGLE_PUT_MAX) {
    await request("PUT", path(bucket, key), { headers: { "content-type": contentType(file) }, body: file, signal });
    progress(file.size, file.size);
    return;
  }
  const created = await xml("POST", path(bucket, key), {
    query: { uploads: "" },
    headers: { "content-type": contentType(file) },
    signal,
  });
  const uploadId = parseUploadId(created);
  if (!uploadId) throw new Error("The server didn't start the upload.");
  const parts = planParts(file.size);
  const done = [];
  let sent = 0;
  let next = 0;
  const worker = async () => {
    while (next < parts.length) {
      const part = parts[next++];
      const response = await request("PUT", path(bucket, key), {
        query: { partNumber: String(part.number), uploadId },
        body: file.slice(part.start, part.end),
        signal,
      });
      done.push({ number: part.number, etag: response.headers.get("etag") ?? "" });
      sent += part.end - part.start;
      progress(sent, file.size);
    }
  };
  try {
    await Promise.all(Array.from({ length: Math.min(PARALLEL_PARTS, parts.length) }, worker));
    const completed = await xml("POST", path(bucket, key), {
      query: { uploadId },
      headers: { "content-type": "application/xml" },
      body: completeXml(done),
      signal,
    });
    // S3 may answer 200 and still fail, with an <Error> in the body.
    if (completed?.name === "Error") throw new ApiError(500, text(completed, "Code"), text(completed, "Message"));
  } catch (e) {
    // Leave nothing half-uploaded behind.
    await request("DELETE", path(bucket, key), { query: { uploadId } }).catch(() => {});
    throw e;
  }
}
