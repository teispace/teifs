// S3's and IAM's XML: a small parser for their answers (elements, attributes, text,
// entities, CDATA; no DTDs), and a builder for the documents the page sends.

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/** Decodes XML's entities and character references in `text`. */
export function unescape(text) {
  return text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-z]+);/g, (whole, ref) => {
    if (ref[0] === "#") {
      const code = ref[1] === "x" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[ref] ?? whole;
  });
}

/** Escapes `text` for XML's text and attribute values. */
export function escape(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Parses `source` into `{ name, attrs, children, text }` nodes (names without their
 * namespace prefix); `text` is the element's own text, joined. Throws on XML that
 * doesn't close.
 */
export function parse(source) {
  const root = { name: "#document", attrs: {}, children: [], text: "" };
  const stack = [root];
  let i = 0;
  const n = source.length;
  while (i < n) {
    const lt = source.indexOf("<", i);
    if (lt < 0) {
      stack[stack.length - 1].text += unescape(source.slice(i));
      break;
    }
    if (lt > i) stack[stack.length - 1].text += unescape(source.slice(i, lt));
    if (source.startsWith("<?", lt)) {
      i = closeAt(source, "?>", lt) + 2;
    } else if (source.startsWith("<!--", lt)) {
      i = closeAt(source, "-->", lt) + 3;
    } else if (source.startsWith("<![CDATA[", lt)) {
      const end = closeAt(source, "]]>", lt);
      stack[stack.length - 1].text += source.slice(lt + 9, end);
      i = end + 3;
    } else if (source.startsWith("<!", lt)) {
      throw new Error("XML with a DTD isn't read");
    } else if (source[lt + 1] === "/") {
      const end = closeAt(source, ">", lt);
      const name = local(source.slice(lt + 2, end).trim());
      const open = stack.pop();
      if (!open || open === root || open.name !== name) throw new Error(`unexpected </${name}>`);
      i = end + 1;
    } else {
      const end = tagEnd(source, lt);
      let body = source.slice(lt + 1, end);
      const selfClosing = body.endsWith("/");
      if (selfClosing) body = body.slice(0, -1);
      const match = /^([^\s/>]+)/.exec(body);
      if (!match) throw new Error("an element without a name");
      const node = { name: local(match[1]), attrs: attributes(body.slice(match[1].length)), children: [], text: "" };
      stack[stack.length - 1].children.push(node);
      if (!selfClosing) stack.push(node);
      i = end + 1;
    }
  }
  if (stack.length !== 1) throw new Error("XML that doesn't close");
  const [first] = root.children;
  if (!first) throw new Error("XML without an element");
  return first;
}

function closeAt(source, marker, from) {
  const at = source.indexOf(marker, from);
  if (at < 0) throw new Error("XML that doesn't close");
  return at;
}

/** Where the tag starting at `from` ends: its `>`, outside quoted values. */
function tagEnd(source, from) {
  let quote = null;
  for (let i = from + 1; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === ">") {
      return i;
    }
  }
  throw new Error("XML that doesn't close");
}

function local(name) {
  const colon = name.indexOf(":");
  return colon < 0 ? name : name.slice(colon + 1);
}

function attributes(text) {
  const attrs = {};
  const re = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(text))) attrs[local(m[1])] = unescape(m[3] ?? m[4] ?? "");
  return attrs;
}

/** The first child of `node` named `name`. */
export function child(node, name) {
  return node?.children.find((c) => c.name === name);
}

/** Every child of `node` named `name`. */
export function children(node, name) {
  return node ? node.children.filter((c) => c.name === name) : [];
}

/** The text of `node`'s first child named `name`, or `fallback`. */
export function text(node, name, fallback = "") {
  const found = child(node, name);
  return found ? found.text : fallback;
}

/** The first element named `name` anywhere under `node`, `node` included. */
export function find(node, name) {
  if (!node) return undefined;
  if (node.name === name) return node;
  for (const c of node.children) {
    const found = find(c, name);
    if (found) return found;
  }
  return undefined;
}

/**
 * An XML document's text from a tree of `[name, ...content]` arrays, where content is
 * strings (text), nested arrays, or `null` (skipped):
 * `build(["VersioningConfiguration", ["Status", "Enabled"]])`.
 */
export function build(tree, namespace = "http://s3.amazonaws.com/doc/2006-03-01/") {
  return `<?xml version="1.0" encoding="UTF-8"?>${element(tree, namespace)}`;
}

function element([name, ...content], namespace) {
  const ns = namespace ? ` xmlns="${escape(namespace)}"` : "";
  const inner = content
    .filter((c) => c !== null && c !== undefined && c !== false)
    .map((c) => (Array.isArray(c) ? element(c, null) : escape(c)))
    .join("");
  return `<${name}${ns}>${inner}</${name}>`;
}
