// The AWS SDK for JavaScript v3 against TeiFS: what applications do with it.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  S3Client, CreateBucketCommand, PutObjectCommand, GetObjectCommand, HeadObjectCommand,
  CopyObjectCommand, DeleteObjectsCommand, DeleteBucketCommand, paginateListObjectsV2,
} from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const Bucket = process.env.BUCKET;
const s3 = new S3Client({ endpoint: process.env.ENDPOINT, forcePathStyle: true });
const step = (text) => console.log(`== ${text}`);
const assert = (ok, what) => { if (!ok) throw new Error(`failed: ${what}`); };
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

step("bucket");
await s3.send(new CreateBucketCommand({ Bucket }));

step("put with a checksum (the SDK's default CRC32), get, head");
const small = readFileSync("small.txt");
await s3.send(new PutObjectCommand({ Bucket, Key: "small.txt", Body: small, Metadata: { owner: "js" } }));
const got = await s3.send(new GetObjectCommand({ Bucket, Key: "small.txt" }));
assert(Buffer.from(await got.Body.transformToByteArray()).equals(small), "get returns what was put");
const head = await s3.send(new HeadObjectCommand({ Bucket, Key: "small.txt", ChecksumMode: "ENABLED" }));
assert(head.Metadata.owner === "js", "metadata kept");
assert(head.ChecksumCRC32 || head.ChecksumCRC64NVME, "a checksum is returned");

step("multipart upload through lib-storage, from a stream of unknown length");
const big = readFileSync("big.bin");
await new Upload({
  client: s3,
  params: { Bucket, Key: "big.bin", Body: (await import("node:fs")).createReadStream("big.bin") },
  partSize: 5 * 1024 * 1024,
  queueSize: 4,
}).done();
const back = await s3.send(new GetObjectCommand({ Bucket, Key: "big.bin" }));
assert(sha(Buffer.from(await back.Body.transformToByteArray())) === sha(big), "multipart round trip");
const range = await s3.send(new GetObjectCommand({ Bucket, Key: "big.bin", Range: "bytes=10-19" }));
assert(Buffer.from(await range.Body.transformToByteArray()).equals(big.subarray(10, 20)), "range");

step("copy, paginate, delete many");
await s3.send(new CopyObjectCommand({ Bucket, Key: "copy.txt", CopySource: `${Bucket}/small.txt` }));
for (let i = 0; i < 12; i++) {
  await s3.send(new PutObjectCommand({ Bucket, Key: `many/${String(i).padStart(3, "0")}`, Body: "x" }));
}
const keys = [];
for await (const page of paginateListObjectsV2({ client: s3, pageSize: 5 }, { Bucket, Prefix: "many/" })) {
  keys.push(...(page.Contents ?? []).map((o) => o.Key));
}
assert(keys.length === 12 && keys[0] === "many/000" && keys[11] === "many/011", "pagination");

step("presigned GET");
const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket, Key: "small.txt" }), { expiresIn: 60 });
const linked = Buffer.from(await (await fetch(url)).arrayBuffer());
assert(linked.equals(small), "presigned link");

step("empty and remove the bucket");
const all = [];
for await (const page of paginateListObjectsV2({ client: s3 }, { Bucket })) {
  all.push(...(page.Contents ?? []).map((o) => ({ Key: o.Key })));
}
await s3.send(new DeleteObjectsCommand({ Bucket, Delete: { Objects: all } }));
await s3.send(new DeleteBucketCommand({ Bucket }));
console.log("ok");
