// Unit tests for the page's pure modules: `node --test crates/console/web/test/*.test.js`.
// No dependencies: Node's own test runner and assertions.

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseError, queryString } from "../lib/api.js";
import { bytes, duration } from "../lib/format.js";
import { bucketNameProblem, encodeKey, parseBuckets, path, versioningXml } from "../lib/s3.js";
import { build, child, children, escape, find, parse, text, unescape } from "../lib/xml.js";

test("xml: parses S3's answers, namespaces, entities and CDATA", () => {
  const root = parse(`<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <!-- a comment -->
  <Owner><ID>abc</ID><DisplayName>a &amp; b</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>one</Name><CreationDate>2026-11-17T10:00:00.000Z</CreationDate></Bucket>
    <Bucket><Name>two</Name><CreationDate>2026-11-16T10:00:00.000Z</CreationDate></Bucket>
  </Buckets>
  <x:Odd x:attr='q"uote'><![CDATA[<raw> & text]]></x:Odd>
  <Empty/>
</ListAllMyBucketsResult>`);
  assert.equal(root.name, "ListAllMyBucketsResult");
  assert.equal(root.attrs.xmlns, "http://s3.amazonaws.com/doc/2006-03-01/");
  assert.equal(text(child(root, "Owner"), "DisplayName"), "a & b");
  assert.equal(children(child(root, "Buckets"), "Bucket").length, 2);
  assert.equal(child(root, "Odd").text, "<raw> & text");
  assert.equal(child(root, "Odd").attrs.attr, 'q"uote');
  assert.equal(text(root, "Empty", "none"), "");
  assert.equal(text(root, "Missing", "none"), "none");
  assert.equal(find(root, "Name").text, "one");
});

test("xml: keys keep their spaces and character references", () => {
  const root = parse("<Contents><Key>  a&#x20;b&#9;c &#128512; </Key></Contents>");
  assert.equal(text(root, "Key"), "  a b\tc \u{1F600} ");
  assert.equal(unescape("&bogus; &#xZZ;"), "&bogus; &#xZZ;");
});

test("xml: refuses what doesn't close, DTDs and mismatched tags", () => {
  assert.throws(() => parse("<a><b></a>"));
  assert.throws(() => parse("<a>"));
  assert.throws(() => parse('<!DOCTYPE x [<!ENTITY e "boom">]><a>&e;</a>'));
  assert.throws(() => parse("just text"));
});

test("xml: builds documents with escaped text", () => {
  assert.equal(escape(`<a href="x">&'</a>`), "&lt;a href=&quot;x&quot;&gt;&amp;&apos;&lt;/a&gt;");
  assert.equal(
    build(["Tagging", ["TagSet", ["Tag", ["Key", "a<b"], ["Value", "c&d"]], null]]),
    '<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>a&lt;b</Key><Value>c&amp;d</Value></Tag></TagSet></Tagging>',
  );
  assert.equal(
    versioningXml("Enabled"),
    '<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>',
  );
});

test("s3: keys are encoded as Signature V4 signs them", () => {
  assert.equal(encodeKey("a b/c+d.txt"), "a%20b/c%2Bd.txt");
  assert.equal(encodeKey("café/~x_y-z"), "caf%C3%A9/~x_y-z");
  assert.equal(encodeKey("!*'()?#%"), "%21%2A%27%28%29%3F%23%25");
  assert.equal(path("photos"), "/api/s3/photos");
  assert.equal(path("photos", "2026/a b.jpg"), "/api/s3/photos/2026/a%20b.jpg");
});

test("s3: bucket names follow S3's rules", () => {
  assert.equal(bucketNameProblem("photos"), "");
  assert.equal(bucketNameProblem("my.bucket-1"), "");
  for (const bad of ["ab", "a".repeat(64), "Photos", "under_score", "-start", "end-", "a..b", "192.168.1.1", "xn--abc", "abc-s3alias", "abc--x-s3"]) {
    assert.notEqual(bucketNameProblem(bad), "", bad);
  }
});

test("s3: ListBuckets' answer is read", () => {
  const listed = parseBuckets(
    parse(
      "<ListAllMyBucketsResult><Owner><ID>id</ID></Owner><Buckets><Bucket><Name>b</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate><BucketRegion>us-east-1</BucketRegion></Bucket></Buckets><ContinuationToken>next</ContinuationToken></ListAllMyBucketsResult>",
    ),
  );
  assert.deepEqual(listed, {
    owner: "id",
    buckets: [{ name: "b", created: "2026-01-01T00:00:00Z", region: "us-east-1" }],
    continuation: "next",
  });
});

test("api: errors are read from S3, IAM and the console", () => {
  const s3 = parseError(403, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>", "application/xml");
  assert.equal(s3.code, "AccessDenied");
  assert.equal(s3.message, "Access Denied");
  const iam = parseError(
    404,
    "<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>no user</Message></Error></ErrorResponse>",
    "text/xml",
  );
  assert.equal(iam.code, "NoSuchEntity");
  const console = parseError(401, '{"code":"SignedOut","message":"Sign in"}', "application/json");
  assert.equal(console.code, "SignedOut");
  assert.equal(parseError(403, "", "").message, "Access denied.");
  assert.equal(parseError(500, "<html>", "").message, "HTTP 500");
});

test("api: query strings are sorted, encoded, and subresources have no value", () => {
  assert.equal(queryString({ versioning: "" }), "?versioning");
  assert.equal(queryString({ prefix: "a b/", "list-type": "2", delimiter: "/", x: undefined }), "?delimiter=%2F&list-type=2&prefix=a%20b%2F");
  assert.equal(queryString({}), "");
});

test("format: sizes and durations", () => {
  assert.equal(bytes(0), "0 B");
  assert.equal(bytes(1023), "1023 B");
  assert.equal(bytes(1536), "1.50 KiB");
  assert.equal(bytes(10 * 1024 * 1024), "10.0 MiB");
  assert.equal(bytes(-1), "");
  assert.equal(duration(42), "42 s");
  assert.equal(duration(3 * 3600 + 5 * 60), "3 h 5 min");
  assert.equal(duration(2 * 86400), "2 d");
});
