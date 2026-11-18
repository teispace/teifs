// IAM: users and their access keys, groups, and managed and inline policies.

import { announce, confirmAction, dialog, h, mount } from "../lib/dom.js";
import { dateTime } from "../lib/format.js";
import { iam, nameProblem } from "../lib/iam.js";
import { policyProblem } from "../lib/settings.js";

const enc = encodeURIComponent;

/** A titled section that fills itself with `load(body)`, showing its error if it fails. */
function section(title, load) {
  const body = h("div", {}, h("p", { class: "loading" }, "Loading…"));
  const reload = () => load(body, reload).catch((e) => mount(body, h("p", { class: "error", role: "alert" }, e.message)));
  reload();
  return h("section", { class: "card setting" }, h("h2", {}, title), body);
}

async function run(done, action, after) {
  try {
    await action();
    if (done) announce(done);
    after?.();
  } catch (e) {
    announce(e.message, "error");
  }
}

/** Asks for one name (and validates it); "" when cancelled. */
async function askName(title, label, max) {
  const input = h("input", { id: "ask-name", required: true, spellcheck: "false", autocapitalize: "none" });
  const answer = await dialog(title, h("div", { class: "form" }, h("label", { for: "ask-name" }, label), input), [
    { label: "Cancel", value: "" },
    { label: "Create", value: "ok", class: "primary" },
  ]);
  if (answer !== "ok") return "";
  const why = nameProblem(input.value.trim(), max);
  if (why) {
    announce(why, "error");
    return "";
  }
  return input.value.trim();
}

/** Asks for a policy document (JSON), checked before it's sent; null when cancelled. */
async function askDocument(title, initial = "", { withName = false } = {}) {
  const name = h("input", { id: "doc-name", spellcheck: "false" });
  const editor = h("textarea", { id: "doc-json", rows: "14", spellcheck: "false" }, initial || '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "s3:GetObject",\n      "Resource": "arn:aws:s3:::BUCKET/*"\n    }\n  ]\n}');
  const answer = await dialog(
    title,
    h("div", { class: "form" }, withName ? [h("label", { for: "doc-name" }, "Name"), name] : null, h("label", { for: "doc-json" }, "Policy (JSON)"), editor),
    [
      { label: "Cancel", value: "" },
      { label: "Save", value: "ok", class: "primary" },
    ],
  );
  if (answer !== "ok") return null;
  const why = policyProblem(editor.value) || (withName ? nameProblem(name.value.trim(), 128) : "");
  if (why) {
    announce(why, "error");
    return null;
  }
  return { name: name.value.trim(), document: editor.value };
}

function table(headings, rows, empty) {
  if (!rows.length) return h("p", { class: "empty" }, empty);
  return h(
    "table",
    { class: "list compact" },
    h("thead", {}, h("tr", {}, headings.map((t, i) => h("th", { scope: "col" }, i === headings.length - 1 && !t ? h("span", { class: "visually-hidden" }, "Actions") : t)))),
    h("tbody", {}, rows),
  );
}

/** Managed policies attached to a user or group (`kind` `User` or `Group`). */
function managedSection(kind, name) {
  return section("Managed policies", async (body, reload) => {
    const [attached, all] = await Promise.all([iam.attached(kind, name), iam.policies("All").catch(() => [])]);
    const choices = all.filter((p) => !attached.some((a) => a.arn === p.arn));
    const pick = h("select", { "aria-label": "Policy to attach" }, choices.map((p) => h("option", { value: p.arn }, p.name)));
    mount(
      body,
      table(
        ["Policy", ""],
        attached.map((p) =>
          h(
            "tr",
            {},
            h("th", { scope: "row" }, h("a", { href: `#/policy/${enc(p.arn)}` }, p.name)),
            h("td", { class: "actions" }, h("button", { type: "button", class: "small", onclick: () => run(`Detached ${p.name}.`, () => iam.detach(kind, name, p.arn), reload) }, "Detach")),
          ),
        ),
        "No managed policies attached.",
      ),
      choices.length
        ? h("div", { class: "actions left" }, pick, h("button", { type: "button", onclick: () => run("Attached the policy.", () => iam.attach(kind, name, pick.value), reload) }, "Attach"))
        : null,
    );
  });
}

/** Inline policies of a user or group. */
function inlineSection(kind, name) {
  return section("Inline policies", async (body, reload) => {
    const names = await iam.inline(kind, name);
    const edit = async (policy) => {
      const current = await iam.inlineDocument(kind, name, policy);
      const changed = await askDocument(`Inline policy ${policy}`, current);
      if (changed) run(`Saved ${policy}.`, () => iam.putInline(kind, name, policy, changed.document), reload);
    };
    mount(
      body,
      table(
        ["Policy", ""],
        names.map((p) =>
          h(
            "tr",
            {},
            h("th", { scope: "row" }, p),
            h(
              "td",
              { class: "actions" },
              h("button", { type: "button", class: "small", onclick: () => edit(p).catch((e) => announce(e.message, "error")) }, "Edit"),
              " ",
              h(
                "button",
                {
                  type: "button",
                  class: "danger small",
                  onclick: async () => {
                    if (await confirmAction("Delete inline policy", `Delete ${p}?`, "Delete")) run(`Deleted ${p}.`, () => iam.deleteInline(kind, name, p), reload);
                  },
                },
                "Delete",
              ),
            ),
          ),
        ),
        "No inline policies.",
      ),
      h(
        "div",
        { class: "actions left" },
        h(
          "button",
          {
            type: "button",
            onclick: async () => {
              const added = await askDocument("New inline policy", "", { withName: true });
              if (added) run(`Saved ${added.name}.`, () => iam.putInline(kind, name, added.name, added.document), reload);
            },
          },
          "Add inline policy",
        ),
      ),
    );
  });
}

/** Shows a new access key's secret, once. */
async function showNewKey(key) {
  const copy = (value) => () => navigator.clipboard?.writeText(value).then(() => announce("Copied."));
  await dialog(
    "New access key",
    h(
      "div",
      { class: "form" },
      h("p", { class: "warning" }, "Copy the secret key now: it's shown only this once."),
      h("label", { for: "new-key-id" }, "Access key"),
      h("div", { class: "copy-row" }, h("input", { id: "new-key-id", readonly: true, value: key.id }), h("button", { type: "button", onclick: copy(key.id) }, "Copy")),
      h("label", { for: "new-key-secret" }, "Secret key"),
      h("div", { class: "copy-row" }, h("input", { id: "new-key-secret", readonly: true, value: key.secret }), h("button", { type: "button", onclick: copy(key.secret) }, "Copy")),
    ),
    [{ label: "Done", value: "ok", class: "primary" }],
  );
}

function keysSection(user) {
  return section("Access keys", async (body, reload) => {
    const keys = await iam.accessKeys(user);
    mount(
      body,
      table(
        ["Access key", "Status", "Created", ""],
        keys.map((k) =>
          h(
            "tr",
            {},
            h("th", { scope: "row" }, h("code", {}, k.id)),
            h("td", {}, k.status),
            h("td", {}, dateTime(k.created)),
            h(
              "td",
              { class: "actions" },
              h(
                "button",
                { type: "button", class: "small", onclick: () => run(`Key ${k.status === "Active" ? "deactivated" : "activated"}.`, () => iam.setKeyStatus(user, k.id, k.status === "Active" ? "Inactive" : "Active"), reload) },
                k.status === "Active" ? "Deactivate" : "Activate",
              ),
              " ",
              h(
                "button",
                {
                  type: "button",
                  class: "danger small",
                  onclick: async () => {
                    if (await confirmAction("Delete access key", `Delete ${k.id}? Anything signing with it stops working.`, "Delete")) run("Deleted the key.", () => iam.deleteAccessKey(user, k.id), reload);
                  },
                },
                "Delete",
              ),
            ),
          ),
        ),
        "No access keys.",
      ),
      h(
        "div",
        { class: "actions left" },
        h(
          "button",
          {
            type: "button",
            class: "primary",
            disabled: keys.length >= 2,
            title: keys.length >= 2 ? "A user has at most two access keys." : null,
            onclick: async () => {
              try {
                const key = await iam.createAccessKey(user);
                await showNewKey(key);
              } catch (e) {
                announce(e.message, "error");
              }
              reload();
            },
          },
          "Create access key",
        ),
      ),
    );
  });
}

function userGroupsSection(user) {
  return section("Groups", async (body, reload) => {
    const [mine, all] = await Promise.all([iam.groupsOf(user), iam.groups()]);
    const choices = all.filter((g) => !mine.some((m) => m.name === g.name));
    const pick = h("select", { "aria-label": "Group to join" }, choices.map((g) => h("option", { value: g.name }, g.name)));
    mount(
      body,
      table(
        ["Group", ""],
        mine.map((g) =>
          h(
            "tr",
            {},
            h("th", { scope: "row" }, h("a", { href: `#/group/${enc(g.name)}` }, g.name)),
            h("td", { class: "actions" }, h("button", { type: "button", class: "small", onclick: () => run(`Removed from ${g.name}.`, () => iam.removeFromGroup(g.name, user), reload) }, "Remove")),
          ),
        ),
        "In no groups.",
      ),
      choices.length ? h("div", { class: "actions left" }, pick, h("button", { type: "button", onclick: () => run("Added to the group.", () => iam.addToGroup(pick.value, user), reload) }, "Add to group")) : null,
    );
  });
}

function iamTabs(current) {
  return h(
    "nav",
    { class: "tabs", "aria-label": "IAM" },
    [
      ["users", "Users"],
      ["groups", "Groups"],
      ["policies", "Policies"],
    ].map(([route, label]) => h("a", { href: `#/${route}`, "aria-current": route === current ? "page" : null }, label)),
  );
}

/** The user list. */
export async function users(main) {
  mount(main, iamTabs("users"), h("p", { class: "loading" }, "Loading users…"));
  const refresh = () => users(main);
  let list;
  try {
    list = await iam.users();
  } catch (e) {
    mount(main, iamTabs("users"), h("h1", {}, "Users"), h("p", { class: "error", role: "alert" }, e.message));
    return;
  }
  mount(
    main,
    iamTabs("users"),
    h(
      "div",
      { class: "title-row" },
      h("h1", {}, "Users"),
      h(
        "button",
        {
          type: "button",
          class: "primary",
          onclick: async () => {
            const name = await askName("Create user", "User name", 64);
            if (name) run(`Created ${name}.`, () => iam.createUser(name), () => (location.hash = `#/user/${enc(name)}`));
          },
        },
        "Create user",
      ),
    ),
    table(
      ["Name", "Created", ""],
      list.map((u) =>
        h(
          "tr",
          {},
          h("th", { scope: "row" }, h("a", { href: `#/user/${enc(u.name)}` }, u.name)),
          h("td", {}, dateTime(u.created)),
          h(
            "td",
            { class: "actions" },
            h(
              "button",
              {
                type: "button",
                class: "danger small",
                "aria-label": `Delete user ${u.name}`,
                onclick: async () => {
                  if (await confirmAction("Delete user", `Delete ${u.name}, with its access keys and policies?`, "Delete")) run(`Deleted ${u.name}.`, () => iam.deleteUser(u.name), refresh);
                },
              },
              "Delete",
            ),
          ),
        ),
      ),
      "No IAM users yet.",
    ),
  );
}

/** One user: keys, groups, policies. */
export function user(main, name) {
  mount(
    main,
    iamTabs("users"),
    h("nav", { class: "crumbs", "aria-label": "User" }, h("a", { href: "#/users" }, "Users"), " / ", h("span", { "aria-current": "page" }, name)),
    h("h1", {}, name),
    h("div", { class: "settings" }, keysSection(name), userGroupsSection(name), managedSection("User", name), inlineSection("User", name)),
  );
}

/** The group list. */
export async function groups(main) {
  mount(main, iamTabs("groups"), h("p", { class: "loading" }, "Loading groups…"));
  const refresh = () => groups(main);
  let list;
  try {
    list = await iam.groups();
  } catch (e) {
    mount(main, iamTabs("groups"), h("h1", {}, "Groups"), h("p", { class: "error", role: "alert" }, e.message));
    return;
  }
  mount(
    main,
    iamTabs("groups"),
    h(
      "div",
      { class: "title-row" },
      h("h1", {}, "Groups"),
      h(
        "button",
        {
          type: "button",
          class: "primary",
          onclick: async () => {
            const name = await askName("Create group", "Group name", 128);
            if (name) run(`Created ${name}.`, () => iam.createGroup(name), refresh);
          },
        },
        "Create group",
      ),
    ),
    table(
      ["Name", "Created", ""],
      list.map((g) =>
        h(
          "tr",
          {},
          h("th", { scope: "row" }, h("a", { href: `#/group/${enc(g.name)}` }, g.name)),
          h("td", {}, dateTime(g.created)),
          h(
            "td",
            { class: "actions" },
            h(
              "button",
              {
                type: "button",
                class: "danger small",
                "aria-label": `Delete group ${g.name}`,
                onclick: async () => {
                  if (await confirmAction("Delete group", `Delete ${g.name}? Its members stay; they leave the group.`, "Delete")) run(`Deleted ${g.name}.`, () => iam.deleteGroup(g.name), refresh);
                },
              },
              "Delete",
            ),
          ),
        ),
      ),
      "No groups yet.",
    ),
  );
}

/** One group: members and policies. */
export function group(main, name) {
  const membersSection = section("Members", async (body, reload) => {
    const [inGroup, all] = await Promise.all([iam.groupUsers(name), iam.users()]);
    const choices = all.filter((u) => !inGroup.some((m) => m.name === u.name));
    const pick = h("select", { "aria-label": "User to add" }, choices.map((u) => h("option", { value: u.name }, u.name)));
    mount(
      body,
      table(
        ["User", ""],
        inGroup.map((u) =>
          h(
            "tr",
            {},
            h("th", { scope: "row" }, h("a", { href: `#/user/${enc(u.name)}` }, u.name)),
            h("td", { class: "actions" }, h("button", { type: "button", class: "small", onclick: () => run(`Removed ${u.name}.`, () => iam.removeFromGroup(name, u.name), reload) }, "Remove")),
          ),
        ),
        "No members.",
      ),
      choices.length ? h("div", { class: "actions left" }, pick, h("button", { type: "button", onclick: () => run("Added the user.", () => iam.addToGroup(name, pick.value), reload) }, "Add user")) : null,
    );
  });
  mount(
    main,
    iamTabs("groups"),
    h("nav", { class: "crumbs", "aria-label": "Group" }, h("a", { href: "#/groups" }, "Groups"), " / ", h("span", { "aria-current": "page" }, name)),
    h("h1", {}, name),
    h("div", { class: "settings" }, membersSection, managedSection("Group", name), inlineSection("Group", name)),
  );
}

let showAwsManaged = false;

/** The managed policy list: the account's own, and the built-in ones on request. */
export async function policies(main) {
  mount(main, iamTabs("policies"), h("p", { class: "loading" }, "Loading policies…"));
  const refresh = () => policies(main);
  let list;
  try {
    list = await iam.policies(showAwsManaged ? "All" : "Local");
  } catch (e) {
    mount(main, iamTabs("policies"), h("h1", {}, "Policies"), h("p", { class: "error", role: "alert" }, e.message));
    return;
  }
  const toggle = h("input", {
    type: "checkbox",
    id: "aws-managed",
    checked: showAwsManaged,
    onchange: (e) => {
      showAwsManaged = e.target.checked;
      refresh();
    },
  });
  mount(
    main,
    iamTabs("policies"),
    h(
      "div",
      { class: "title-row" },
      h("h1", {}, "Policies"),
      h(
        "div",
        { class: "toolbar" },
        h("span", { class: "check" }, toggle, h("label", { for: "aws-managed" }, "Show built-in policies")),
        h(
          "button",
          {
            type: "button",
            class: "primary",
            onclick: async () => {
              const created = await askDocument("Create policy", "", { withName: true });
              if (created) run(`Created ${created.name}.`, () => iam.createPolicy(created.name, created.document), refresh);
            },
          },
          "Create policy",
        ),
      ),
    ),
    table(
      ["Name", "Attached to", "Updated"],
      list.map((p) =>
        h(
          "tr",
          {},
          h("th", { scope: "row" }, h("a", { href: `#/policy/${enc(p.arn)}` }, p.name)),
          h("td", {}, String(p.attachments)),
          h("td", {}, dateTime(p.updated)),
        ),
      ),
      showAwsManaged ? "No policies." : "No policies of the account's own yet.",
    ),
  );
}

/** One managed policy: its document, versions; editing makes a new default version. */
export function policy(main, arn) {
  const builtIn = !arn.includes(":iam::") || arn.includes(":iam::aws:");
  const details = section("Document", async (body, reload) => {
    const info = await iam.policy(arn);
    const document = await iam.policyDocument(arn, info.defaultVersion);
    const editor = h("textarea", { id: "policy-doc", rows: "18", spellcheck: "false", readonly: builtIn }, document);
    const problem = h("p", { class: "error", role: "alert", hidden: true });
    mount(
      body,
      h("p", { class: "muted" }, h("code", {}, arn), ` · version ${info.defaultVersion} · attached to ${info.attachments}`),
      h("label", { for: "policy-doc", class: "visually-hidden" }, "Policy document"),
      editor,
      problem,
      builtIn
        ? h("p", { class: "muted" }, "Built-in policies can't be changed.")
        : h(
            "div",
            { class: "actions left" },
            h(
              "button",
              {
                type: "button",
                class: "primary",
                onclick: () => {
                  const why = policyProblem(editor.value);
                  problem.textContent = why;
                  problem.hidden = !why;
                  if (!why) run("Saved a new version.", () => iam.updatePolicy(arn, editor.value), reload);
                },
              },
              "Save as new version",
            ),
            h(
              "button",
              {
                type: "button",
                class: "danger",
                onclick: async () => {
                  if (await confirmAction("Delete policy", `Delete ${info.name}? Detach it from every user and group first.`, "Delete")) {
                    run(`Deleted ${info.name}.`, () => iam.deletePolicy(arn), () => (location.hash = "#/policies"));
                  }
                },
              },
              "Delete policy",
            ),
          ),
    );
  });
  mount(
    main,
    iamTabs("policies"),
    h("nav", { class: "crumbs", "aria-label": "Policy" }, h("a", { href: "#/policies" }, "Policies"), " / ", h("span", { "aria-current": "page" }, arn.split("/").pop())),
    h("h1", {}, arn.split("/").pop()),
    h("div", { class: "settings" }, details),
  );
}
