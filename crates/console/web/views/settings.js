// A bucket's settings: versioning, default encryption, tags, policy and lifecycle, each
// read and saved on its own, so a key allowed some of them can still use those.

import { announce, confirmAction, h, mount } from "../lib/dom.js";
import { addRule, bucket, expirationRule, lifecycleProblem, parseLifecycle, policyProblem, prettyPolicy, tagsProblem } from "../lib/settings.js";
import { parse } from "../lib/xml.js";
import { browseHash } from "./objects.js";

/** The fragment that opens `name`'s settings. */
export function settingsHash(name) {
  return `#/s/${encodeURIComponent(name)}`;
}

/** A card for one setting: loads with `load(card)`, which fills it, or says why it can't. */
function card(title, id, load) {
  const body = h("div", { class: "card-body" }, h("p", { class: "loading" }, "Loading…"));
  const section = h("section", { class: "card setting", "aria-labelledby": id }, h("h2", { id }, title), body);
  load(body).catch((e) => mount(body, h("p", { class: "error", role: "alert" }, e.message)));
  return section;
}

async function saving(what, action, reload) {
  try {
    await action();
    announce(`Saved ${what}.`);
    reload?.();
  } catch (e) {
    announce(e.message, "error");
  }
}

function versioningCard(name) {
  const load = async (body) => {
    const status = await bucket.versioning(name);
    const shown = status || "Never enabled";
    const set = (to) => saving("versioning", () => bucket.setVersioning(name, to), () => load(body));
    mount(
      body,
      h("p", {}, "Status: ", h("strong", {}, shown)),
      h("p", { class: "muted" }, "With versioning on, overwriting or deleting an object keeps its earlier versions. Once on, it can be suspended, not turned off."),
      h(
        "div",
        { class: "actions left" },
        status === "Enabled"
          ? h("button", { type: "button", onclick: () => set("Suspended") }, "Suspend versioning")
          : h("button", { type: "button", class: "primary", onclick: () => set("Enabled") }, "Enable versioning"),
      ),
    );
  };
  return card("Versioning", "versioning", load);
}

function encryptionCard(name) {
  const load = async (body) => {
    const current = (await bucket.encryption(name)) ?? { algorithm: "AES256", keyId: "", bucketKey: false };
    const algorithm = h(
      "select",
      { id: "sse-algorithm" },
      [
        ["AES256", "SSE-S3 (keys TeiFS manages)"],
        ["aws:kms", "SSE-KMS (a KMS key)"],
        ["aws:kms:dsse", "DSSE-KMS (two layers)"],
      ].map(([value, label]) => h("option", { value, selected: value === current.algorithm }, label)),
    );
    const keyId = h("input", { id: "sse-key", value: current.keyId, spellcheck: "false", placeholder: "the server's default key" });
    const bucketKey = h("input", { id: "sse-bucket-key", type: "checkbox", checked: current.bucketKey });
    const kmsOnly = h("div", { class: "form" }, h("label", { for: "sse-key" }, "KMS key"), keyId, h("div", { class: "check" }, bucketKey, h("label", { for: "sse-bucket-key" }, "Bucket key")));
    const toggle = () => {
      kmsOnly.hidden = !algorithm.value.startsWith("aws:kms");
    };
    algorithm.addEventListener("change", toggle);
    toggle();
    mount(
      body,
      h("p", { class: "muted" }, "New objects are encrypted this way unless a request asks for another."),
      h("div", { class: "form" }, h("label", { for: "sse-algorithm" }, "Default encryption"), algorithm),
      kmsOnly,
      h(
        "div",
        { class: "actions left" },
        h(
          "button",
          {
            type: "button",
            class: "primary",
            onclick: () =>
              saving("encryption", () => bucket.setEncryption(name, { algorithm: algorithm.value, keyId: keyId.value.trim(), bucketKey: bucketKey.checked }), () => load(body)),
          },
          "Save encryption",
        ),
      ),
    );
  };
  return card("Default encryption", "encryption", load);
}

function tagsCard(name) {
  const load = async (body) => {
    const rows = h("tbody", {});
    const problem = h("p", { class: "error", role: "alert", hidden: true });
    const addRow = (tag = { key: "", value: "" }) => {
      const n = rows.children.length;
      const row = h(
        "tr",
        {},
        h("td", {}, h("input", { "aria-label": `Tag ${n + 1} key`, value: tag.key, class: "tag-key" })),
        h("td", {}, h("input", { "aria-label": `Tag ${n + 1} value`, value: tag.value, class: "tag-value" })),
        h("td", { class: "actions" }, h("button", { type: "button", class: "small", "aria-label": `Remove tag ${n + 1}`, onclick: () => row.remove() }, "Remove")),
      );
      rows.append(row);
    };
    for (const tag of await bucket.tags(name)) addRow(tag);
    const read = () =>
      [...rows.children].map((r) => ({ key: r.querySelector(".tag-key").value.trim(), value: r.querySelector(".tag-value").value }));
    mount(
      body,
      h("table", { class: "list compact" }, h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Key"), h("th", { scope: "col" }, "Value"), h("th", { scope: "col" }, h("span", { class: "visually-hidden" }, "Actions")))), rows),
      problem,
      h(
        "div",
        { class: "actions left" },
        h("button", { type: "button", onclick: () => addRow() }, "Add tag"),
        h(
          "button",
          {
            type: "button",
            class: "primary",
            onclick: () => {
              const tags = read().filter((t) => t.key || t.value);
              const why = tagsProblem(tags);
              problem.textContent = why;
              problem.hidden = !why;
              if (!why) saving("tags", () => bucket.setTags(name, tags), () => load(body));
            },
          },
          "Save tags",
        ),
      ),
    );
  };
  return card("Tags", "tags", load);
}

function policyCard(name) {
  const load = async (body) => {
    const policy = await bucket.policy(name);
    const editor = h("textarea", { id: "policy", rows: "14", spellcheck: "false", "aria-describedby": "policy-help" }, prettyPolicy(policy));
    const problem = h("p", { class: "error", role: "alert", hidden: true });
    mount(
      body,
      h("p", { class: "muted", id: "policy-help" }, "Who else may do what with this bucket, as an IAM policy document in JSON."),
      h("label", { for: "policy", class: "visually-hidden" }, "Bucket policy"),
      editor,
      problem,
      h(
        "div",
        { class: "actions left" },
        h(
          "button",
          {
            type: "button",
            class: "primary",
            onclick: () => {
              const why = editor.value.trim() ? policyProblem(editor.value) : "";
              problem.textContent = why;
              problem.hidden = !why;
              if (!why) saving("the policy", () => bucket.setPolicy(name, editor.value.trim()), () => load(body));
            },
          },
          "Save policy",
        ),
        policy
          ? h(
              "button",
              {
                type: "button",
                class: "danger",
                onclick: async () => {
                  if (await confirmAction("Delete policy", `Delete ${name}'s bucket policy?`, "Delete")) saving("the policy", () => bucket.setPolicy(name, ""), () => load(body));
                },
              },
              "Delete policy",
            )
          : null,
      ),
    );
  };
  return card("Bucket policy", "policy", load);
}

function lifecycleCard(name) {
  const load = async (body) => {
    const document = await bucket.lifecycle(name);
    let rules = [];
    try {
      rules = document ? parseLifecycle(parse(document)) : [];
    } catch {
      rules = [];
    }
    const editor = h("textarea", { id: "lifecycle", rows: "12", spellcheck: "false" }, document);
    const problem = h("p", { class: "error", role: "alert", hidden: true });
    const ruleId = h("input", { id: "rule-id", value: `expire-${rules.length + 1}` });
    const rulePrefix = h("input", { id: "rule-prefix", placeholder: "every object", spellcheck: "false" });
    const ruleDays = h("input", { id: "rule-days", type: "number", min: "1", inputmode: "numeric" });
    const ruleOld = h("input", { id: "rule-old", type: "number", min: "1", inputmode: "numeric" });
    const ruleAbort = h("input", { id: "rule-abort", type: "number", min: "1", value: "7", inputmode: "numeric" });
    const field = (input, label) => h("div", { class: "field" }, h("label", { for: input.id }, label), input);
    mount(
      body,
      rules.length
        ? h(
            "table",
            { class: "list compact" },
            h("thead", {}, h("tr", {}, ["Rule", "Status", "Prefix", "Expire after", "Old versions after", "Abort uploads after"].map((t) => h("th", { scope: "col" }, t)))),
            h(
              "tbody",
              {},
              rules.map((r) =>
                h(
                  "tr",
                  {},
                  h("th", { scope: "row" }, r.id || "(no id)"),
                  h("td", {}, r.status),
                  h("td", {}, r.prefix || "every object"),
                  h("td", {}, r.expirationDays ? `${r.expirationDays} days` : ""),
                  h("td", {}, r.noncurrentDays ? `${r.noncurrentDays} days` : ""),
                  h("td", {}, r.abortDays ? `${r.abortDays} days` : ""),
                ),
              ),
            ),
          )
        : h("p", { class: "muted" }, "No lifecycle rules: objects stay until they're deleted."),
      h(
        "details",
        {},
        h("summary", {}, "Add an expiration rule"),
        h("div", { class: "grid" }, field(ruleId, "Rule id"), field(rulePrefix, "Prefix"), field(ruleDays, "Expire objects after (days)"), field(ruleOld, "Expire old versions after (days)"), field(ruleAbort, "Abort unfinished uploads after (days)")),
        h(
          "button",
          {
            type: "button",
            onclick: () => {
              try {
                editor.value = addRule(editor.value, expirationRule({ id: ruleId.value.trim(), prefix: rulePrefix.value, days: ruleDays.value, noncurrentDays: ruleOld.value, abortDays: ruleAbort.value }));
                editor.focus();
              } catch (e) {
                announce(e.message, "error");
              }
            },
          },
          "Add to the configuration below",
        ),
      ),
      h("label", { for: "lifecycle" }, "Configuration (XML)"),
      editor,
      problem,
      h(
        "div",
        { class: "actions left" },
        h(
          "button",
          {
            type: "button",
            class: "primary",
            onclick: () => {
              const why = editor.value.trim() ? lifecycleProblem(editor.value) : "";
              problem.textContent = why;
              problem.hidden = !why;
              if (!why) saving("the lifecycle", () => bucket.setLifecycle(name, editor.value.trim()), () => load(body));
            },
          },
          "Save lifecycle",
        ),
        document
          ? h(
              "button",
              {
                type: "button",
                class: "danger",
                onclick: async () => {
                  if (await confirmAction("Delete lifecycle", `Delete every lifecycle rule of ${name}?`, "Delete")) saving("the lifecycle", () => bucket.setLifecycle(name, ""), () => load(body));
                },
              },
              "Delete lifecycle",
            )
          : null,
      ),
    );
  };
  return card("Lifecycle", "lifecycle", load);
}

/** Shows `name`'s settings in `main`. */
export function settings(main, name) {
  mount(
    main,
    h("nav", { class: "crumbs", "aria-label": "Bucket" }, h("a", { href: "#/buckets" }, "Buckets"), " / ", h("a", { href: browseHash(name) }, name), " / ", h("span", { "aria-current": "page" }, "Settings")),
    h("h1", {}, `${name} settings`),
    h("div", { class: "settings" }, versioningCard(name), encryptionCard(name), tagsCard(name), policyCard(name), lifecycleCard(name)),
  );
}
