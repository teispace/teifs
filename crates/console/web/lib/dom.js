// Building the page's nodes: h() makes elements from plain values, never from HTML
// strings, so text from the server (object keys, error messages) is always text.

/**
 * An element: `h("button", { class: "primary", onclick: go }, "Save")`.
 * Attributes: `class`, `for`, `on<event>` (a listener), booleans (`true` sets,
 * `false`/`null` leaves out), anything else as a string. Children: nodes, strings,
 * numbers, arrays of them; `null`, `undefined` and `false` are skipped.
 */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs ?? {})) {
    if (value === null || value === undefined || value === false) continue;
    if (name.startsWith("on") && typeof value === "function") {
      el.addEventListener(name.slice(2), value);
    } else if (name === "class") {
      el.className = value;
    } else if (name === "for") {
      el.htmlFor = value;
    } else if (name === "value" && "value" in el) {
      el.value = value;
    } else if (value === true) {
      el.setAttribute(name, "");
    } else {
      el.setAttribute(name, String(value));
    }
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(el, child);
    else if (child instanceof Node) el.append(child);
    else el.append(document.createTextNode(String(child)));
  }
}

/** Replaces what `el` holds with `children`. */
export function mount(el, ...children) {
  el.replaceChildren();
  append(el, children);
}

/** Says `message` in the status region (read out by screen readers). */
export function announce(message, kind = "info") {
  const status = document.getElementById("status");
  if (!status) return;
  status.dataset.kind = kind;
  status.textContent = message;
  clearTimeout(announce.timer);
  announce.timer = setTimeout(() => {
    status.textContent = "";
  }, 6000);
}

/**
 * A modal dialog; resolves with the button's value (or "" when dismissed), and gives
 * focus back to whatever had it.
 */
export function dialog(title, body, buttons) {
  const before = document.activeElement;
  return new Promise((resolve) => {
    const d = h(
      "dialog",
      { class: "dialog", "aria-labelledby": "dialog-title" },
      h("h2", { id: "dialog-title" }, title),
      h("div", { class: "dialog-body" }, body),
      h(
        "div",
        { class: "actions" },
        buttons.map((b) =>
          h(
            "button",
            {
              type: "button",
              class: b.class ?? "",
              onclick: () => d.close(b.value),
            },
            b.label,
          ),
        ),
      ),
    );
    d.addEventListener("close", () => {
      d.remove();
      if (before instanceof HTMLElement) before.focus();
      resolve(d.returnValue);
    });
    document.body.append(d);
    d.showModal();
  });
}

/** Asks to confirm something destructive. */
export async function confirmAction(title, message, label) {
  const answer = await dialog(title, h("p", {}, message), [
    { label: "Cancel", value: "" },
    { label, value: "yes", class: "danger" },
  ]);
  return answer === "yes";
}
