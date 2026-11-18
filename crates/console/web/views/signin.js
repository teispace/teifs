// Signing in with an access key: the secret goes to the server once, which keeps it
// for the session; the page keeps nothing.

import { session } from "../lib/api.js";
import { h, mount } from "../lib/dom.js";

/** Shows the sign-in form in `main`; calls `done(who)` once signed in. */
export function signIn(main, done) {
  const error = h("p", { class: "error", id: "signin-error", role: "alert", hidden: true });
  const access = h("input", {
    id: "access-key",
    name: "username",
    autocomplete: "username",
    required: true,
    spellcheck: "false",
    autocapitalize: "none",
  });
  const secret = h("input", {
    id: "secret-key",
    name: "password",
    type: "password",
    autocomplete: "current-password",
    required: true,
  });
  const token = h("textarea", { id: "session-token", rows: "3", spellcheck: "false" });
  const button = h("button", { type: "submit", class: "primary" }, "Sign in");
  const form = h(
    "form",
    {
      class: "signin card",
      "aria-describedby": "signin-error",
      onsubmit: async (event) => {
        event.preventDefault();
        error.hidden = true;
        button.disabled = true;
        try {
          const who = await session.signIn(access.value.trim(), secret.value, token.value.trim());
          secret.value = "";
          token.value = "";
          done(who);
        } catch (e) {
          error.textContent = e.message;
          error.hidden = false;
          secret.focus();
        } finally {
          button.disabled = false;
        }
      },
    },
    h("h1", {}, "Sign in to TeiFS"),
    h("p", { class: "muted" }, "Use an access key of the root user or an IAM user. What you can do here is what the key's policies allow."),
    h("label", { for: "access-key" }, "Access key"),
    access,
    h("label", { for: "secret-key" }, "Secret key"),
    secret,
    h(
      "details",
      {},
      h("summary", {}, "Temporary credentials"),
      h("label", { for: "session-token" }, "Session token"),
      token,
    ),
    error,
    button,
  );
  mount(main, form);
  access.focus();
}
