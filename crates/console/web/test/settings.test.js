// Unit tests for buckets' settings documents.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  addRule,
  encryptionXml,
  expirationRule,
  lifecycleProblem,
  parseEncryption,
  parseLifecycle,
  parseTags,
  parseVersioning,
  policyProblem,
  prettyPolicy,
  taggingXml,
  tagsProblem,
} from "../lib/settings.js";
import { parse } from "../lib/xml.js";

test("versioning and encryption are read and written", () => {
  assert.equal(parseVersioning(parse("<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>")), "Suspended");
  assert.equal(parseVersioning(parse("<VersioningConfiguration/>")), "");
  const sse = parseEncryption(
    parse(
      "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>k1</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>",
    ),
  );
  assert.deepEqual(sse, { algorithm: "aws:kms", keyId: "k1", bucketKey: true });
  assert.match(encryptionXml({ algorithm: "AES256", keyId: "ignored", bucketKey: true }), /<SSEAlgorithm>AES256<\/SSEAlgorithm><\/ApplyServerSideEncryptionByDefault><\/Rule>/);
  assert.match(encryptionXml(sse), /<KMSMasterKeyID>k1<\/KMSMasterKeyID><\/ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true/);
});

test("tags follow S3's limits", () => {
  const tags = parseTags(parse("<Tagging><TagSet><Tag><Key>team</Key><Value>a&amp;b</Value></Tag></TagSet></Tagging>"));
  assert.deepEqual(tags, [{ key: "team", value: "a&b" }]);
  assert.match(taggingXml(tags), /<Key>team<\/Key><Value>a&amp;b<\/Value>/);
  assert.equal(tagsProblem(tags), "");
  assert.notEqual(tagsProblem([{ key: "", value: "x" }]), "");
  assert.notEqual(tagsProblem([{ key: "a", value: "" }, { key: "a", value: "" }]), "");
  assert.notEqual(tagsProblem([{ key: "aws:x", value: "" }]), "");
  assert.notEqual(tagsProblem([{ key: "k".repeat(129), value: "" }]), "");
  assert.notEqual(tagsProblem(Array.from({ length: 51 }, (_, i) => ({ key: `k${i}`, value: "" }))), "");
});

test("policies are checked as JSON and shown indented", () => {
  assert.equal(policyProblem('{"Version":"2012-10-17","Statement":[]}'), "");
  assert.notEqual(policyProblem("{"), "");
  assert.notEqual(policyProblem("[]"), "");
  assert.notEqual(policyProblem('{"Version":"2012-10-17"}'), "");
  assert.equal(prettyPolicy('{"a":1}'), '{\n  "a": 1\n}');
  assert.equal(prettyPolicy("not json"), "not json");
});

test("lifecycle rules are summarised and added", () => {
  const rule = expirationRule({ id: "old<logs>", prefix: "logs/", days: "30", noncurrentDays: "", abortDays: "7" });
  assert.equal(
    rule,
    "<Rule><ID>old&lt;logs&gt;</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>",
  );
  const document = addRule("", rule);
  assert.equal(lifecycleProblem(document), "");
  const twice = addRule(document, expirationRule({ id: "versions", noncurrentDays: "90" }));
  const rules = parseLifecycle(parse(twice));
  assert.deepEqual(
    rules.map((r) => [r.id, r.status, r.prefix, r.expirationDays, r.noncurrentDays, r.abortDays]),
    [
      ["old<logs>", "Enabled", "logs/", "30", "", "7"],
      ["versions", "Enabled", "", "", "90", ""],
    ],
  );
  assert.throws(() => addRule("<Other/>", rule));
  assert.notEqual(lifecycleProblem("<LifecycleConfiguration></LifecycleConfiguration>"), "");
  assert.notEqual(lifecycleProblem("<Tagging/>"), "");
  assert.notEqual(lifecycleProblem("<Lifecycle"), "");
  // The older form, a rule's Prefix outside a Filter, is read too.
  assert.equal(parseLifecycle(parse("<LifecycleConfiguration><Rule><Prefix>a/</Prefix><Status>Disabled</Status></Rule></LifecycleConfiguration>"))[0].prefix, "a/");
});
