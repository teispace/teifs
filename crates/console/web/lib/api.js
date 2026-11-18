// Calls to the console's backend. Every call is same-origin and carries the console's
// header; the session is an HttpOnly cookie the page never sees. S3, IAM and STS calls
// are passed on, signed by the server with the signed-in key, so the answers are
// those APIs' own.

import { child, parse, text } from "./xml.js";

const HEADER = { "x-teifs-console": "1" };

/** An API's refusal: its HTTP status, code (`AccessDenied`, …) and message. */
export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code || `HTTP ${status}`);
    this.status = status;
    this.code = code;
  }
}

let signedOut = () => {};

/** Calls `handler` when a call finds the session ended. */
export function onSignedOut(handler) {
  signedOut = handler;
}

/**
 * The code and message of an error answer's body: the console's JSON, S3's `<Error>`
 * or IAM's and STS's `<ErrorResponse><Error>`.
 */
export function parseError(status, body, type = "") {
  if (type.includes("json")) {
    try {
      const { code, message } = JSON.parse(body);
      return new ApiError(status, code, message);
    } catch {
      return new ApiError(status, "", "");
    }
  }
  try {
    const root = parse(body);
    const error = root.name === "Error" ? root : child(root, "Error");
    if (error) return new ApiError(status, text(error, "Code"), text(error, "Message"));
  } catch {
    // Not XML: say the status.
  }
  return new ApiError(status, "", status === 403 ? "Access denied." : "");
}

/** A query string from an object, keys sorted, `null`/`undefined` left out. */
export function queryString(query = {}) {
  const pairs = Object.entries(query)
    .filter(([, v]) => v !== null && v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => (v === "" ? encodeURIComponent(k) : `${encodeURIComponent(k)}=${encodeURIComponent(v)}`));
  return pairs.length ? `?${pairs.join("&")}` : "";
}

/** Sends a call to `path` (`/api/…`); throws an `ApiError` unless it succeeds. */
export async function request(method, path, { query, headers = {}, body, signal } = {}) {
  const response = await fetch(path + queryString(query), {
    method,
    headers: { ...HEADER, ...headers },
    body,
    signal,
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) {
    const error = parseError(response.status, await response.text(), response.headers.get("content-type") ?? "");
    if (response.status === 401 && error.code === "SignedOut") signedOut();
    throw error;
  }
  return response;
}

/** A call whose answer is XML: its root element. */
export async function xml(method, path, options) {
  const response = await request(method, path, options);
  const body = await response.text();
  return body.trim() ? parse(body) : null;
}

/** A call whose answer is JSON. */
export async function json(method, path, options) {
  const response = await request(method, path, options);
  return response.json();
}

/** An IAM or STS (Query protocol) call: `Action` and its parameters, form-encoded. */
export function query(service, action, params = {}) {
  const form = new URLSearchParams({ Action: action, Version: service === "sts" ? "2011-06-15" : "2010-05-08" });
  for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined) form.append(k, v);
  return xml("POST", `/api/${service}`, {
    headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
    body: form.toString(),
  });
}

/** The session: who is signed in, signing in and out. */
export const session = {
  /** Who is signed in, or null. */
  async current() {
    try {
      return await json("GET", "/api/session");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return null;
      throw e;
    }
  },
  signIn(accessKey, secretKey, sessionToken) {
    return json("POST", "/api/session", {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ accessKey, secretKey, sessionToken: sessionToken || null }),
    });
  },
  async signOut() {
    await request("DELETE", "/api/session");
  },
};
