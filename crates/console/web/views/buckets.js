// The bucket list: every bucket the key may list, creating and deleting them.

import { announce, confirmAction, dialog, h, mount } from "../lib/dom.js";
import { dateTime } from "../lib/format.js";
import { bucketNameProblem, createBucket, deleteBucket, listBuckets } from "../lib/s3.js";
import { browseHash } from "./objects.js";
import { settingsHash } from "./settings.js";

/** Shows the bucket list in `main`. */
export async function buckets(main) {
  const heading = h("h1", {}, "Buckets");
  mount(main, heading, h("p", { class: "loading" }, "Loading buckets…"));
  let list;
  try {
    list = await listBuckets();
  } catch (e) {
    mount(main, heading, h("p", { class: "error", role: "alert" }, e.message));
    return;
  }
  const refresh = () => buckets(main);
  mount(
    main,
    h(
      "div",
      { class: "title-row" },
      heading,
      h("button", { type: "button", class: "primary", onclick: () => create(refresh) }, "Create bucket"),
    ),
    list.length
      ? h(
          "table",
          { class: "list" },
          h("caption", { class: "visually-hidden" }, `${list.length} buckets`),
          h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Name"), h("th", { scope: "col" }, "Created"), h("th", { scope: "col" }, h("span", { class: "visually-hidden" }, "Actions")))),
          h(
            "tbody",
            {},
            list.map((b) =>
              h(
                "tr",
                {},
                h("th", { scope: "row" }, h("a", { href: browseHash(b.name) }, b.name)),
                h("td", {}, dateTime(b.created)),
                h(
                  "td",
                  { class: "actions" },
                  h("a", { href: settingsHash(b.name), class: "button small", "aria-label": `Settings of ${b.name}` }, "Settings"),
                  " ",
                  h(
                    "button",
                    { type: "button", class: "danger small", "aria-label": `Delete bucket ${b.name}`, onclick: () => remove(b.name, refresh) },
                    "Delete",
                  ),
                ),
              ),
            ),
          ),
        )
      : h("p", { class: "empty" }, "No buckets yet."),
  );
}

async function create(refresh) {
  const name = h("input", { id: "bucket-name", required: true, spellcheck: "false", autocapitalize: "none", "aria-describedby": "bucket-name-help" });
  const help = h("p", { id: "bucket-name-help", class: "muted" }, "3–63 lowercase letters, digits, dots and hyphens.");
  const lock = h("input", { id: "bucket-lock", type: "checkbox" });
  const layout = h(
    "select",
    { id: "bucket-layout", "aria-describedby": "bucket-layout-help" },
    h("option", { value: "" }, "The server's default"),
    h("option", { value: "object" }, "Object: any key, encryption, Object Lock"),
    h("option", { value: "folder" }, "Folder: keys are files and folders on the drive"),
  );
  const problem = h("p", { class: "error", role: "alert", hidden: true });
  name.addEventListener("input", () => {
    const why = name.value ? bucketNameProblem(name.value) : "";
    problem.textContent = why;
    problem.hidden = !why;
  });
  const answer = await dialog(
    "Create bucket",
    h(
      "div",
      { class: "form" },
      h("label", { for: "bucket-name" }, "Name"),
      name,
      help,
      h("label", { for: "bucket-layout" }, "Layout"),
      layout,
      h("p", { id: "bucket-layout-help", class: "muted" }, "How TeiFS stores the bucket's objects on its drive."),
      h("div", { class: "check" }, lock, h("label", { for: "bucket-lock" }, "Object Lock (turns versioning on; can't be turned off)")),
      problem,
    ),
    [
      { label: "Cancel", value: "" },
      { label: "Create", value: "create", class: "primary" },
    ],
  );
  if (answer !== "create") return;
  const why = bucketNameProblem(name.value);
  if (why) {
    announce(why, "error");
    return;
  }
  try {
    await createBucket(name.value, { objectLock: lock.checked, layout: layout.value });
    announce(`Created bucket ${name.value}.`);
    refresh();
  } catch (e) {
    announce(e.message, "error");
  }
}

async function remove(name, refresh) {
  if (!(await confirmAction("Delete bucket", `Delete the bucket ${name}? Only an empty bucket can be deleted.`, "Delete"))) return;
  try {
    await deleteBucket(name);
    announce(`Deleted bucket ${name}.`);
    refresh();
  } catch (e) {
    announce(e.message, "error");
  }
}
