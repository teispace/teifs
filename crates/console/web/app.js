// The console's shell: who is signed in, the navigation, the theme, and the routes
// (`#/buckets`, `#/b/BUCKET/PREFIX`, …) read from the URL's fragment.

import { onSignedOut, session } from "./lib/api.js";
import { announce, h, mount } from "./lib/dom.js";
import { buckets } from "./views/buckets.js";
import { group, groups, policies, policy, user, users } from "./views/iam.js";
import { objects } from "./views/objects.js";
import { settings } from "./views/settings.js";
import { signIn } from "./views/signin.js";

const THEMES = ["system", "light", "dark"];
const main = document.getElementById("main");
const top = document.getElementById("top");
let who = null;

function storedTheme() {
  try {
    return localStorage.getItem("teifs-theme") || "system";
  } catch {
    return "system";
  }
}

function applyTheme(theme) {
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem("teifs-theme", theme);
  } catch {
    // Private windows may refuse: the theme lasts for this page.
  }
}

function shell() {
  const theme = h(
    "select",
    {
      id: "theme",
      "aria-label": "Theme",
      onchange: (e) => applyTheme(e.target.value),
    },
    THEMES.map((t) => h("option", { value: t, selected: t === storedTheme() }, t[0].toUpperCase() + t.slice(1))),
  );
  mount(
    top,
    h("a", { class: "brand", href: "#/buckets" }, h("img", { src: "favicon.svg", alt: "", width: "24", height: "24" }), "TeiFS"),
    h(
      "nav",
      { "aria-label": "Main" },
      h("a", { href: "#/buckets", "data-route": "buckets" }, "Buckets"),
      h("a", { href: "#/users", "data-route": "iam" }, "Identity and access"),
    ),
    h(
      "div",
      { class: "who" },
      h("span", { class: "muted", title: who.arn }, who.arn.split(":").pop()),
      theme,
      h("button", { type: "button", onclick: signOut }, "Sign out"),
    ),
  );
  top.hidden = false;
}

async function signOut() {
  try {
    await session.signOut();
  } finally {
    who = null;
    top.hidden = true;
    location.hash = "";
    showSignIn();
  }
}

function showSignIn() {
  top.hidden = true;
  signIn(main, (signedIn) => {
    who = signedIn;
    shell();
    route();
  });
}

/** The navigation's section a route belongs to. */
function section(name) {
  if (["b", "s"].includes(name)) return "buckets";
  if (["users", "user", "groups", "group", "policies", "policy"].includes(name)) return "iam";
  return name;
}

/** The route the fragment names: `[name, ...parts]`, parts decoded. */
export function parseRoute(hash) {
  const parts = hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  return parts[0] ? parts : ["buckets"];
}

function route() {
  if (!who) return;
  const [name, ...parts] = parseRoute(location.hash);
  for (const link of top.querySelectorAll("nav a")) {
    if (link.dataset.route === section(name)) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  switch (name) {
    case "buckets":
      buckets(main);
      break;
    case "b":
      objects(main, parts[0], parts[1] ?? "");
      break;
    case "s":
      settings(main, parts[0]);
      break;
    case "users":
      users(main);
      break;
    case "user":
      user(main, parts[0]);
      break;
    case "groups":
      groups(main);
      break;
    case "group":
      group(main, parts[0]);
      break;
    case "policies":
      policies(main);
      break;
    case "policy":
      policy(main, parts.join("/"));
      break;
    default:
      mount(main, h("h1", {}, "Not found"), h("p", {}, "There's no such page."), h("a", { href: "#/buckets" }, "Back to buckets"));
  }
  main.focus({ preventScroll: true });
}

async function start() {
  applyTheme(storedTheme());
  onSignedOut(() => {
    if (who) announce("Your session ended: sign in again.", "error");
    who = null;
    showSignIn();
  });
  window.addEventListener("hashchange", route);
  try {
    who = await session.current();
  } catch (e) {
    mount(main, h("p", { class: "error", role: "alert" }, e.message));
    return;
  }
  if (who) {
    shell();
    route();
  } else {
    showSignIn();
  }
}

start();
