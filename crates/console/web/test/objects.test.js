// Unit tests for the object browser's pure parts: listings, deletes, multipart uploads.

import assert from "node:assert/strict";
import { test } from "node:test";

import { deleteXml, downloadLink, parseDeleteErrors, parseObjects, parseVersions } from "../lib/s3.js";
import { MAX_PARTS, PART_SIZE, completeXml, parseUploadId, planParts } from "../lib/upload.js";
import { parse } from "../lib/xml.js";
import { browseHash, crumbs, shortName } from "../views/objects.js";

const MiB = 1024 * 1024;

test("ListObjectsV2's answer is read, with its next page", () => {
  const page = parseObjects(
    parse(`<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t2</NextContinuationToken>
      <Contents><Key>a/one.txt</Key><Size>5</Size><LastModified>2026-11-17T10:00:00.000Z</LastModified><ETag>"abc"</ETag><StorageClass>STANDARD</StorageClass></Contents>
      <CommonPrefixes><Prefix>a/b/</Prefix></CommonPrefixes></ListBucketResult>`),
  );
  assert.deepEqual(page.prefixes, ["a/b/"]);
  assert.deepEqual(page.objects, [{ key: "a/one.txt", size: 5, modified: "2026-11-17T10:00:00.000Z", etag: '"abc"', storageClass: "STANDARD" }]);
  assert.equal(page.next, "t2");
  assert.equal(parseObjects(parse("<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>")).next, "");
});

test("ListObjectVersions' answer keeps versions and delete markers in order", () => {
  const listed = parseVersions(
    parse(`<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>k</NextKeyMarker><NextVersionIdMarker>v</NextVersionIdMarker>
      <DeleteMarker><Key>x</Key><VersionId>3</VersionId><IsLatest>true</IsLatest><LastModified>t3</LastModified></DeleteMarker>
      <Version><Key>x</Key><VersionId>2</VersionId><IsLatest>false</IsLatest><Size>10</Size><LastModified>t2</LastModified><ETag>"e"</ETag></Version>
    </ListVersionsResult>`),
  );
  assert.deepEqual(
    listed.versions.map((v) => [v.versionId, v.latest, v.deleteMarker, v.size]),
    [
      ["3", true, true, 0],
      ["2", false, false, 10],
    ],
  );
  assert.deepEqual(listed.next, { keyMarker: "k", versionIdMarker: "v" });
});

test("DeleteObjects' request and failures", () => {
  assert.equal(
    deleteXml([{ key: "a&b" }, { key: "c", versionId: "v1" }]),
    '<?xml version="1.0" encoding="UTF-8"?><Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Quiet>true</Quiet><Object><Key>a&amp;b</Key></Object><Object><Key>c</Key><VersionId>v1</VersionId></Object></Delete>',
  );
  assert.deepEqual(
    parseDeleteErrors(parse("<DeleteResult><Error><Key>k</Key><Code>AccessDenied</Code><Message>no</Message></Error></DeleteResult>")),
    [{ key: "k", versionId: "", code: "AccessDenied", message: "no" }],
  );
  assert.equal(downloadLink("b", "a b/c.txt"), "/api/download/b/a%20b/c.txt");
  assert.equal(downloadLink("b", "k", "v+1"), "/api/download/b/k?versionId=v%2B1");
});

test("files are cut into parts S3 takes", () => {
  assert.deepEqual(planParts(0), [{ number: 1, start: 0, end: 0 }]);
  const parts = planParts(40 * MiB);
  assert.deepEqual(
    parts.map((p) => [p.number, p.start, p.end]),
    [
      [1, 0, 16 * MiB],
      [2, 16 * MiB, 32 * MiB],
      [3, 32 * MiB, 40 * MiB],
    ],
  );
  // A huge file gets bigger parts, never more than S3's 10,000.
  const huge = 5 * 1024 * 1024 * MiB; // 5 TiB
  const many = planParts(huge);
  assert.ok(many.length <= MAX_PARTS, `${many.length} parts`);
  assert.equal(many.at(-1).end, huge);
  assert.ok(many[0].end - many[0].start > PART_SIZE);
  assert.equal((many[0].end - many[0].start) % MiB, 0);
});

test("multipart uploads' documents", () => {
  assert.equal(
    completeXml([
      { number: 2, etag: '"b"' },
      { number: 1, etag: '"a"' },
    ]),
    '<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Part><PartNumber>1</PartNumber><ETag>&quot;a&quot;</ETag></Part><Part><PartNumber>2</PartNumber><ETag>&quot;b&quot;</ETag></Part></CompleteMultipartUpload>',
  );
  assert.equal(parseUploadId(parse("<InitiateMultipartUploadResult><Bucket>b</Bucket><UploadId>u-1</UploadId></InitiateMultipartUploadResult>")), "u-1");
});

test("the browser's names, breadcrumbs and links", () => {
  assert.equal(shortName("a/b/c.txt", "a/b/"), "c.txt");
  assert.equal(shortName("a/b/", "a/"), "b/");
  assert.deepEqual(crumbs("a/b c/"), [
    { label: "a", prefix: "a/" },
    { label: "b c", prefix: "a/b c/" },
  ]);
  assert.deepEqual(crumbs(""), []);
  assert.equal(browseHash("photos", "2026/a b/"), "#/b/photos/2026%2Fa%20b%2F");
});
