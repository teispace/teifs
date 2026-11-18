// Unit tests for IAM's answers as the console reads them.

import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeDocument, members, nameProblem, nextMarker, parse } from "../lib/iam.js";
import { parse as xml } from "../lib/xml.js";

const NS = 'xmlns="https://iam.amazonaws.com/doc/2010-05-08/"';

test("lists are read from their Result's members, with the marker that continues them", () => {
  const root = xml(`<ListUsersResponse ${NS}><ListUsersResult><IsTruncated>true</IsTruncated><Marker>m2</Marker><Users>
    <member><UserName>ana</UserName><UserId>AIDA1</UserId><Arn>arn:aws:iam::123456789012:user/ana</Arn><Path>/</Path><CreateDate>2026-11-17T10:00:00Z</CreateDate></member>
    <member><UserName>bo</UserName><UserId>AIDA2</UserId><Arn>arn:aws:iam::123456789012:user/bo</Arn><Path>/</Path><CreateDate>2026-11-17T11:00:00Z</CreateDate></member>
  </Users></ListUsersResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListUsersResponse>`);
  assert.equal(members(root, "Users").length, 2);
  assert.deepEqual(parse.users(root)[0], { name: "ana", id: "AIDA1", arn: "arn:aws:iam::123456789012:user/ana", path: "/", created: "2026-11-17T10:00:00Z" });
  assert.equal(nextMarker(root), "m2");
  assert.equal(nextMarker(xml("<ListUsersResponse><ListUsersResult><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>")), "");
});

test("keys, policies and attachments", () => {
  const keys = parse.accessKeys(
    xml("<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata><member><AccessKeyId>AKIA1</AccessKeyId><Status>Inactive</Status><CreateDate>d</CreateDate></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>"),
  );
  assert.deepEqual(keys, [{ id: "AKIA1", status: "Inactive", created: "d" }]);
  const created = parse.newKey(
    xml("<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><UserName>ana</UserName><AccessKeyId>AKIA2</AccessKeyId><Status>Active</Status><SecretAccessKey>s3cr3t</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>"),
  );
  assert.deepEqual(created, { id: "AKIA2", secret: "s3cr3t", status: "Active" });
  const policies = parse.policies(
    xml("<ListPoliciesResponse><ListPoliciesResult><Policies><member><PolicyName>read</PolicyName><Arn>arn:aws:iam::1:policy/read</Arn><DefaultVersionId>v2</DefaultVersionId><AttachmentCount>3</AttachmentCount><UpdateDate>u</UpdateDate></member></Policies></ListPoliciesResult></ListPoliciesResponse>"),
  );
  assert.equal(policies[0].attachments, 3);
  assert.equal(policies[0].defaultVersion, "v2");
  assert.deepEqual(
    parse.attached(xml("<R><ListAttachedUserPoliciesResult><AttachedPolicies><member><PolicyName>p</PolicyName><PolicyArn>arn:p</PolicyArn></member></AttachedPolicies></ListAttachedUserPoliciesResult></R>")),
    [{ name: "p", arn: "arn:p" }],
  );
  assert.deepEqual(parse.inlineNames(xml("<R><ListUserPoliciesResult><PolicyNames><member>a</member><member>b</member></PolicyNames></ListUserPoliciesResult></R>")), ["a", "b"]);
});

test("policy documents are URL-decoded and indented", () => {
  const encoded = encodeURIComponent('{"Version":"2012-10-17","Statement":[]}');
  assert.equal(parse.document(xml(`<R><GetPolicyVersionResult><PolicyVersion><Document>${encoded}</Document><VersionId>v1</VersionId></PolicyVersion></GetPolicyVersionResult></R>`)), '{\n  "Version": "2012-10-17",\n  "Statement": []\n}');
  assert.equal(parse.document(xml(`<R><GetUserPolicyResult><PolicyName>p</PolicyName><PolicyDocument>${encoded}</PolicyDocument></GetUserPolicyResult></R>`)).length > 0, true);
  assert.equal(decodeDocument("%7B%22a%22%3A1%7D"), '{\n  "a": 1\n}');
  assert.equal(decodeDocument("not%ZZjson"), "not%ZZjson");
});

test("names follow IAM's rules", () => {
  assert.equal(nameProblem("ana.b+c@d_e-f"), "");
  assert.notEqual(nameProblem(""), "");
  assert.notEqual(nameProblem("a b"), "");
  assert.notEqual(nameProblem("a/b"), "");
  assert.notEqual(nameProblem("a".repeat(65)), "");
  assert.equal(nameProblem("a".repeat(128), 128), "");
});
