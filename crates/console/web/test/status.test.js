// Unit tests for the status page's reading of the admin APIs' answers.

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseError } from "../lib/api.js";
import { bucketUsage, diskRoom, jobs, problems, scrub } from "../lib/status.js";

// As `GET /.teifs/admin/v1/info` answers.
const info = {
  version: "0.1.0",
  drive: "d9d84ae1",
  account: "899556702750",
  startedMs: 1794935973047,
  uptimeSeconds: 108,
  jobs: {
    sweep: { steps: 3, items: 2, lastProgressMs: 1794935980000, lastError: null },
    lifecycle: { steps: 1, items: 0, lastProgressMs: null, lastError: "disk full" },
  },
  scrub: { last: { startedMs: 1794935000000, finishedMs: 1794935100000, versions: 10, bytes: 2048, damaged: 1, unverifiable: 0, findings: [{ bucket: "b", key: "k", versionId: "null", size: 1, verdict: "damaged" }] } },
  usage: { buckets: 1, objects: 3, versions: 4, deleteMarkers: 0, bytes: 20 },
  disks: [{ path: "/data", total: 1000, free: 50, reserved: 10 }],
};

test("jobs are sorted, with their errors", () => {
  const list = jobs(info);
  assert.deepEqual(
    list.map((j) => j.name),
    ["lifecycle", "sweep"],
  );
  assert.equal(list[0].error, "disk full");
  assert.equal(list[0].lastProgress, "");
  assert.equal(list[1].lastProgress, new Date(1794935980000).toISOString());
  assert.deepEqual(jobs({}), []);
});

test("disks' room and scrubs", () => {
  assert.deepEqual(diskRoom(info.disks[0]), { path: "/data", total: 1000, free: 50, used: 950, reserved: 10, full: 0.95 });
  assert.equal(diskRoom({ path: "/x", total: 0, free: 0, reserved: 0 }).full, 0);
  const { current, last } = scrub(info);
  assert.equal(current, null);
  assert.equal(last.damaged, 1);
  assert.deepEqual(last.findings, [{ bucket: "b", key: "k", versionId: "null" }]);
  assert.deepEqual(scrub({ scrub: {} }), { current: null, last: null });
});

test("problems name failed jobs, damage and full disks", () => {
  const found = problems(info);
  assert.equal(found.length, 3);
  assert.match(found[0], /lifecycle job failed: disk full/);
  assert.match(found[1], /1 damaged version\./);
  assert.match(found[2], /\/data is 95% full/);
  assert.match(problems({ disks: [{ path: "/d", total: 100, free: 5, reserved: 10 }] })[0], /is full/);
  assert.deepEqual(problems({ jobs: { a: { lastError: null } }, disks: [{ path: "/d", total: 100, free: 50, reserved: 1 }] }), []);
});

test("each bucket's usage, biggest first, as MinIO's datausageinfo has it", () => {
  const usage = {
    bucketsUsageInfo: {
      small: { size: 1, objectsCount: 1, versionsCount: 1, deleteMarkersCount: 0 },
      big: { size: 100, objectsCount: 2, versionsCount: 3, deleteMarkersCount: 1 },
    },
  };
  assert.deepEqual(bucketUsage(usage), [
    { name: "big", bytes: 100, objects: 2, versions: 3, deleteMarkers: 1 },
    { name: "small", bytes: 1, objects: 1, versions: 1, deleteMarkers: 0 },
  ]);
  assert.deepEqual(bucketUsage({}), []);
});

test("admin errors are read in either casing", () => {
  const teifs = parseError(403, '{"code":"AccessDenied","message":"No.","requestId":"r"}', "application/json");
  assert.equal(teifs.code, "AccessDenied");
  const minio = parseError(403, '{"Code":"AccessDenied","Message":"Nope.","Resource":"/x","RequestId":"r"}', "application/json");
  assert.equal(minio.code, "AccessDenied");
  assert.equal(minio.message, "Nope.");
});
