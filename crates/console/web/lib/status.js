// The server's status as its admin APIs report it: TeiFS's `info` (version, uptime,
// what the drive holds, its disks, background jobs, scrubs) and MinIO's
// `datausageinfo` (what each bucket holds). Parsers here are pure.

import { json } from "./api.js";

export const INFO_PATH = "/api/s3/.teifs/admin/v1/info";
export const USAGE_PATH = "/api/s3/minio/admin/v3/datausageinfo";

/** A disk's room: used, free for the drive, kept back, and how full it is (0–1). */
export function diskRoom(disk) {
  const total = Number(disk.total) || 0;
  const free = Math.min(Number(disk.free) || 0, total);
  const used = total - free;
  return { path: disk.path, total, free, used, reserved: Number(disk.reserved) || 0, full: total ? used / total : 0 };
}

/** The background jobs, sorted by name, with the last error of each that failed. */
export function jobs(info) {
  return Object.entries(info?.jobs ?? {})
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, job]) => ({
      name,
      steps: job.steps ?? 0,
      items: job.items ?? 0,
      lastProgress: job.lastProgressMs ? new Date(job.lastProgressMs).toISOString() : "",
      error: job.lastError ?? "",
    }));
}

/** What the scrubs found: the pass under way and the last one, or nulls. */
export function scrub(info) {
  const pass = (p) =>
    p
      ? {
          started: new Date(p.startedMs).toISOString(),
          finished: p.finishedMs ? new Date(p.finishedMs).toISOString() : "",
          versions: p.versions ?? 0,
          bytes: p.bytes ?? 0,
          damaged: p.damaged ?? 0,
          unverifiable: p.unverifiable ?? 0,
          findings: (p.findings ?? []).map((f) => ({ bucket: f.bucket, key: f.key, versionId: f.versionId ?? "" })),
        }
      : null;
  return { current: pass(info?.scrub?.current), last: pass(info?.scrub?.last) };
}

/** What each bucket holds, biggest first. */
export function bucketUsage(usage) {
  return Object.entries(usage?.bucketsUsageInfo ?? {})
    .map(([name, b]) => ({ name, bytes: b.size ?? 0, objects: b.objectsCount ?? 0, versions: b.versionsCount ?? 0, deleteMarkers: b.deleteMarkersCount ?? 0 }))
    .sort((a, b) => b.bytes - a.bytes || (a.name < b.name ? -1 : 1));
}

/** Whether anything needs looking at: jobs that failed, damage the scrubs found, full disks. */
export function problems(info) {
  const found = [];
  for (const job of jobs(info)) if (job.error) found.push(`The ${job.name} job failed: ${job.error}`);
  const { last, current } = scrub(info);
  const damaged = Math.max(last?.damaged ?? 0, current?.damaged ?? 0);
  if (damaged) found.push(`The scrub found ${damaged} damaged ${damaged === 1 ? "version" : "versions"}.`);
  for (const disk of (info?.disks ?? []).map(diskRoom)) {
    if (disk.total && disk.free <= disk.reserved) found.push(`${disk.path} is full: writes stop until room is freed.`);
    else if (disk.full >= 0.9) found.push(`${disk.path} is ${Math.round(disk.full * 100)}% full.`);
  }
  return found;
}

export const status = {
  info: () => json("GET", INFO_PATH),
  usage: () => json("GET", USAGE_PATH),
};
