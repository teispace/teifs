// The server's status: version and uptime, what the drive holds and on which disks,
// what each bucket holds, the background jobs and what the scrubs found.

import { h, mount } from "../lib/dom.js";
import { bytes, dateTime, duration } from "../lib/format.js";
import { bucketUsage, diskRoom, jobs, problems, scrub, status as api } from "../lib/status.js";
import { browseHash } from "./objects.js";

const number = (n) => Number(n || 0).toLocaleString();

function figure(label, value) {
  return h("div", { class: "figure" }, h("dt", {}, label), h("dd", {}, value));
}

function card(title, ...body) {
  return h("section", { class: "card setting" }, h("h2", {}, title), ...body);
}

function table(headings, rows, empty) {
  if (!rows.length) return h("p", { class: "empty" }, empty);
  return h("table", { class: "list compact" }, h("thead", {}, h("tr", {}, headings.map((t) => h("th", { scope: "col" }, t)))), h("tbody", {}, rows));
}

function disksCard(info) {
  const disks = (info.disks ?? []).map(diskRoom);
  return card(
    "Disks",
    disks.length
      ? disks.map((d) =>
          h(
            "div",
            { class: "disk" },
            h("p", {}, h("code", {}, d.path)),
            h("meter", { min: "0", max: "1", low: "0.75", high: "0.9", optimum: "0", value: String(d.full), "aria-label": `${d.path}: ${Math.round(d.full * 100)}% used` }),
            h("p", { class: "muted" }, `${bytes(d.used)} used of ${bytes(d.total)} · ${bytes(d.free)} free · ${bytes(d.reserved)} kept free for deletes`),
          ),
        )
      : h("p", { class: "empty" }, "The server didn't say."),
  );
}

function usageCard(info, perBucket) {
  const u = info.usage;
  return card(
    "Usage",
    u
      ? h("dl", { class: "figures" }, figure("Buckets", number(u.buckets)), figure("Objects", number(u.objects)), figure("Versions", number(u.versions)), figure("Delete markers", number(u.deleteMarkers)), figure("Stored", bytes(u.bytes)))
      : h("p", { class: "empty" }, "The server didn't say."),
    perBucket instanceof Error
      ? h("p", { class: "muted" }, `What each bucket holds: ${perBucket.message}`)
      : table(
          ["Bucket", "Stored", "Objects", "Versions", "Delete markers"],
          perBucket.map((b) =>
            h(
              "tr",
              {},
              h("th", { scope: "row" }, h("a", { href: browseHash(b.name, "") }, b.name)),
              h("td", { class: "num" }, bytes(b.bytes)),
              h("td", { class: "num" }, number(b.objects)),
              h("td", { class: "num" }, number(b.versions)),
              h("td", { class: "num" }, number(b.deleteMarkers)),
            ),
          ),
          "No buckets yet.",
        ),
  );
}

function jobsCard(info) {
  return card(
    "Background jobs",
    table(
      ["Job", "Steps", "Items", "Last handled something", "Last error"],
      jobs(info).map((j) =>
        h(
          "tr",
          {},
          h("th", { scope: "row" }, j.name),
          h("td", { class: "num" }, number(j.steps)),
          h("td", { class: "num" }, number(j.items)),
          h("td", {}, j.lastProgress ? dateTime(j.lastProgress) : "Not yet"),
          h("td", { class: j.error ? "error-text" : "muted" }, j.error || "None"),
        ),
      ),
      "No background jobs.",
    ),
  );
}

function scrubCard(info) {
  const { current, last } = scrub(info);
  const pass = (label, p) =>
    p
      ? h(
          "div",
          {},
          h("h3", {}, label),
          h(
            "dl",
            { class: "figures" },
            figure("Started", dateTime(p.started)),
            figure("Finished", p.finished ? dateTime(p.finished) : "Under way"),
            figure("Versions checked", number(p.versions)),
            figure("Read", bytes(p.bytes)),
            figure("Damaged", number(p.damaged)),
            figure("Couldn't check", number(p.unverifiable)),
          ),
          p.findings.length
            ? table(
                ["Bucket", "Key", "Version"],
                p.findings.map((f) => h("tr", {}, h("td", {}, f.bucket), h("td", {}, h("code", {}, f.key)), h("td", {}, h("code", {}, f.versionId)))),
                "",
              )
            : null,
        )
      : null;
  return card("Integrity scrubs", current || last ? [pass("Under way", current), pass("Last finished", last)] : h("p", { class: "empty" }, "No scrub has run since the server started."));
}

/** The status page; `Refresh` reloads it. */
export async function statusPage(main) {
  mount(main, h("h1", {}, "Status"), h("p", { class: "loading" }, "Loading…"));
  let info;
  try {
    info = await api.info();
  } catch (e) {
    mount(main, h("h1", {}, "Status"), h("p", { class: "error", role: "alert" }, e.message));
    return;
  }
  const perBucket = await api.usage().then(bucketUsage, (e) => e);
  const found = problems(info);
  mount(
    main,
    h("div", { class: "title-row" }, h("h1", {}, "Status"), h("button", { type: "button", onclick: () => statusPage(main) }, "Refresh")),
    found.length
      ? h("div", { class: "notice error", role: "alert" }, h("ul", {}, found.map((p) => h("li", {}, p))))
      : h("p", { class: "notice ok" }, "Everything is running."),
    h(
      "section",
      { class: "card setting" },
      h(
        "dl",
        { class: "figures" },
        figure("Version", info.version),
        figure("Running for", duration(info.uptimeSeconds)),
        figure("Started", dateTime(new Date(info.startedMs).toISOString())),
        figure("Account", info.account),
        figure("Drive", h("code", {}, info.drive)),
      ),
    ),
    h("div", { class: "settings" }, usageCard(info, perBucket), disksCard(info), jobsCard(info), scrubCard(info)),
  );
}
