// The object browser: a bucket's folders (key prefixes) and objects, uploading,
// downloading and deleting them, and their versions.

import { announce, confirmAction, dialog, h, mount } from "../lib/dom.js";
import { bytes, dateTime } from "../lib/format.js";
import { allKeys, createFolder, deleteObject, deleteObjects, downloadLink, listObjects, listVersions } from "../lib/s3.js";
import { upload } from "../lib/upload.js";

let showVersions = false;

/** The fragment that opens `prefix` in `bucket`. */
export function browseHash(bucket, prefix = "") {
  return `#/b/${encodeURIComponent(bucket)}/${encodeURIComponent(prefix)}`;
}

/** The part of `key` after `prefix`: what the row shows. */
export function shortName(key, prefix) {
  return key.startsWith(prefix) ? key.slice(prefix.length) : key;
}

/** The breadcrumb's steps for `prefix`: `[{ label, prefix }]`. */
export function crumbs(prefix) {
  const steps = [];
  let at = "";
  for (const part of prefix.split("/").slice(0, -1)) {
    at += `${part}/`;
    steps.push({ label: part || "/", prefix: at });
  }
  return steps;
}

/** Shows `prefix` of `bucket` in `main`. */
export async function objects(main, bucket, prefix = "") {
  const refresh = () => objects(main, bucket, prefix);
  const selected = new Map();
  const deleteSelected = h("button", { type: "button", class: "danger", disabled: true, onclick: () => removeSelected() }, "Delete selected");
  const uploads = h("ul", { class: "uploads", "aria-label": "Uploads" });
  const fileInput = h("input", { type: "file", multiple: true, class: "visually-hidden", id: "upload-files", onchange: (e) => send([...e.target.files]) });
  const folderInput = h("input", { type: "file", multiple: true, webkitdirectory: true, class: "visually-hidden", id: "upload-folder", onchange: (e) => send([...e.target.files]) });
  const versionsToggle = h("input", {
    type: "checkbox",
    id: "show-versions",
    checked: showVersions,
    onchange: (e) => {
      showVersions = e.target.checked;
      refresh();
    },
  });
  const body = h("tbody", {});
  const more = h("div", { class: "more" });
  const table = h(
    "table",
    { class: "list" },
    h("caption", { class: "visually-hidden" }, `Contents of ${bucket}/${prefix}`),
    h(
      "thead",
      {},
      h(
        "tr",
        {},
        h("th", { scope: "col", class: "select" }, h("span", { class: "visually-hidden" }, "Select")),
        h("th", { scope: "col" }, "Name"),
        showVersions ? h("th", { scope: "col" }, "Version") : null,
        h("th", { scope: "col" }, "Size"),
        h("th", { scope: "col" }, "Modified"),
        h("th", { scope: "col" }, h("span", { class: "visually-hidden" }, "Actions")),
      ),
    ),
    body,
  );

  function updateSelection() {
    deleteSelected.disabled = selected.size === 0;
    deleteSelected.textContent = selected.size ? `Delete selected (${selected.size})` : "Delete selected";
  }

  function selectBox(id, entry, label) {
    return h(
      "td",
      { class: "select" },
      h("input", {
        type: "checkbox",
        "aria-label": `Select ${label}`,
        onchange: (e) => {
          if (e.target.checked) selected.set(id, entry);
          else selected.delete(id);
          updateSelection();
        },
      }),
    );
  }

  function folderRow(p) {
    const name = shortName(p, prefix);
    return h(
      "tr",
      {},
      selectBox(`p:${p}`, { prefix: p }, `folder ${name}`),
      h("th", { scope: "row" }, h("a", { href: browseHash(bucket, p), class: "folder" }, name)),
      showVersions ? h("td", {}) : null,
      h("td", {}, ""),
      h("td", {}, ""),
      h("td", {}),
    );
  }

  function objectRow(o) {
    const name = shortName(o.key, prefix);
    return h(
      "tr",
      {},
      selectBox(`k:${o.key}`, { key: o.key }, name),
      h("th", { scope: "row" }, name),
      h("td", {}, bytes(o.size)),
      h("td", {}, dateTime(o.modified)),
      h(
        "td",
        { class: "actions" },
        h("a", { href: downloadLink(bucket, o.key), download: name.split("/").pop() || "download", class: "button small" }, "Download"),
        " ",
        h("button", { type: "button", class: "danger small", "aria-label": `Delete ${name}`, onclick: () => removeOne(o.key) }, "Delete"),
      ),
    );
  }

  function versionRow(v) {
    const name = shortName(v.key, prefix);
    const label = `${name} version ${v.versionId}`;
    return h(
      "tr",
      { class: v.latest ? "latest" : "older" },
      selectBox(`v:${v.key}:${v.versionId}`, { key: v.key, versionId: v.versionId }, label),
      h("th", { scope: "row" }, name),
      h(
        "td",
        { class: "version" },
        h("code", { title: v.versionId }, v.versionId.length > 14 ? `…${v.versionId.slice(-12)}` : v.versionId),
        v.latest ? h("span", { class: "badge" }, "latest") : null,
        v.deleteMarker ? h("span", { class: "badge warn" }, "delete marker") : null,
      ),
      h("td", {}, v.deleteMarker ? "" : bytes(v.size)),
      h("td", {}, dateTime(v.modified)),
      h(
        "td",
        { class: "actions" },
        v.deleteMarker
          ? null
          : h("a", { href: downloadLink(bucket, v.key, v.versionId), download: name.split("/").pop() || "download", class: "button small" }, "Download"),
        " ",
        h(
          "button",
          { type: "button", class: "danger small", "aria-label": `Delete ${label} permanently`, onclick: () => removeVersion(v) },
          "Delete",
        ),
      ),
    );
  }

  async function page(token) {
    more.replaceChildren();
    try {
      if (showVersions) {
        const listed = await listVersions(bucket, prefix, token);
        body.append(...listed.prefixes.map(folderRow), ...listed.versions.filter((v) => v.key !== prefix).map(versionRow));
        if (listed.next) more.append(h("button", { type: "button", onclick: () => page(listed.next) }, "Load more"));
      } else {
        const listed = await listObjects(bucket, prefix, token);
        body.append(...listed.prefixes.map(folderRow), ...listed.objects.filter((o) => o.key !== prefix).map(objectRow));
        if (listed.next) more.append(h("button", { type: "button", onclick: () => page(listed.next) }, "Load more"));
      }
      if (!body.children.length) body.append(h("tr", {}, h("td", { colspan: showVersions ? "6" : "5", class: "empty" }, "This folder is empty. Drop files here to upload them.")));
    } catch (e) {
      more.append(h("p", { class: "error", role: "alert" }, e.message));
    }
  }

  async function send(files) {
    if (!files.length) return;
    for (const file of files) {
      const key = prefix + (file.webkitRelativePath || file.name);
      const bar = h("progress", { max: String(file.size || 1), value: "0", "aria-label": `Uploading ${key}` });
      const state = h("span", { class: "muted" }, "waiting");
      const controller = new AbortController();
      const cancel = h("button", { type: "button", class: "small", onclick: () => controller.abort() }, "Cancel");
      const item = h("li", {}, h("span", { class: "name" }, key), bar, state, cancel);
      uploads.append(item);
      try {
        state.textContent = "uploading";
        await upload(bucket, key, file, {
          signal: controller.signal,
          progress: (sent) => {
            bar.value = sent;
          },
        });
        bar.value = file.size || 1;
        state.textContent = "done";
        cancel.remove();
      } catch (e) {
        state.textContent = e.name === "AbortError" ? "cancelled" : e.message;
        state.className = "error";
        cancel.remove();
      }
    }
    announce(`Uploaded to ${bucket}/${prefix}.`);
    reload();
  }

  /** Lists the folder again, keeping the uploads' progress in view. */
  function reload() {
    body.replaceChildren();
    selected.clear();
    updateSelection();
    page();
  }

  async function newFolder() {
    const input = h("input", { id: "folder-name", required: true, spellcheck: "false" });
    const answer = await dialog("New folder", h("div", { class: "form" }, h("label", { for: "folder-name" }, "Name"), input), [
      { label: "Cancel", value: "" },
      { label: "Create", value: "create", class: "primary" },
    ]);
    const name = input.value.replace(/^\/+|\/+$/g, "");
    if (answer !== "create" || !name) return;
    try {
      await createFolder(bucket, `${prefix}${name}/`);
      refresh();
    } catch (e) {
      announce(e.message, "error");
    }
  }

  async function removeOne(key) {
    if (!(await confirmAction("Delete object", `Delete ${key}?${showVersions ? "" : " In a versioned bucket, this adds a delete marker; older versions stay."}`, "Delete"))) return;
    try {
      await deleteObject(bucket, key);
      announce(`Deleted ${key}.`);
      refresh();
    } catch (e) {
      announce(e.message, "error");
    }
  }

  async function removeVersion(v) {
    if (!(await confirmAction("Delete version", `Permanently delete version ${v.versionId} of ${v.key}? This can't be undone.`, "Delete permanently"))) return;
    try {
      await deleteObject(bucket, v.key, v.versionId);
      announce(`Deleted a version of ${v.key}.`);
      refresh();
    } catch (e) {
      announce(e.message, "error");
    }
  }

  async function removeSelected() {
    const entries = [...selected.values()];
    const folders = entries.filter((e) => e.prefix);
    const message = folders.length
      ? `Delete ${entries.length} selected items? Everything under the selected folders is deleted too.`
      : `Delete ${entries.length} selected items?`;
    if (!(await confirmAction("Delete selected", message, "Delete"))) return;
    try {
      const targets = entries.filter((e) => e.key !== undefined).map((e) => ({ key: e.key, versionId: e.versionId }));
      for (const f of folders) targets.push(...(await allKeys(bucket, f.prefix)));
      const failed = await deleteObjects(bucket, targets);
      if (failed.length) announce(`${failed.length} couldn't be deleted: ${failed[0].key}: ${failed[0].message || failed[0].code}`, "error");
      else announce(`Deleted ${targets.length} objects.`);
      refresh();
    } catch (e) {
      announce(e.message, "error");
    }
  }

  const trail = h(
    "nav",
    { class: "crumbs", "aria-label": "Folder" },
    h("a", { href: "#/buckets" }, "Buckets"),
    " / ",
    prefix ? h("a", { href: browseHash(bucket) }, bucket) : h("span", { "aria-current": "page" }, bucket),
    crumbs(prefix).map((c, i, all) => [" / ", i === all.length - 1 ? h("span", { "aria-current": "page" }, c.label) : h("a", { href: browseHash(bucket, c.prefix) }, c.label)]),
  );
  const drop = h(
    "section",
    {
      class: "browser",
      ondragover: (e) => {
        e.preventDefault();
        drop.classList.add("dropping");
      },
      ondragleave: () => drop.classList.remove("dropping"),
      ondrop: (e) => {
        e.preventDefault();
        drop.classList.remove("dropping");
        send([...(e.dataTransfer?.files ?? [])]);
      },
    },
    table,
    more,
  );
  mount(
    main,
    trail,
    h(
      "div",
      { class: "title-row" },
      h("h1", {}, prefix ? shortName(prefix, crumbs(prefix).at(-2)?.prefix ?? "") : bucket),
      h(
        "div",
        { class: "toolbar" },
        h("label", { for: "upload-files", class: "button primary", tabindex: "0", onkeydown: (e) => e.key === "Enter" && fileInput.click() }, "Upload files"),
        fileInput,
        h("label", { for: "upload-folder", class: "button", tabindex: "0", onkeydown: (e) => e.key === "Enter" && folderInput.click() }, "Upload folder"),
        folderInput,
        h("button", { type: "button", onclick: newFolder }, "New folder"),
        deleteSelected,
        h("span", { class: "check" }, versionsToggle, h("label", { for: "show-versions" }, "Show versions")),
        h("button", { type: "button", onclick: refresh, "aria-label": "Refresh" }, "↻"),
      ),
    ),
    uploads,
    drop,
  );
  await page();
}
