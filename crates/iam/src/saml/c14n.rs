//! Exclusive XML canonicalization (<https://www.w3.org/TR/xml-exc-c14n/>), with or
//! without comments: the bytes an XML signature's digest and signature are over.
//!
//! It's applied to an element and everything in it (what a same-document reference or
//! `SignedInfo` selects), less an enveloped signature. A namespace declaration is
//! written where an element or one of its attributes first uses its prefix, or where
//! `InclusiveNamespaces` asks for it, and not again below while it means the same.

use std::collections::BTreeMap;

use super::xml::{Element, Node};

/// How a subtree is canonicalized.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Options<'a> {
    /// Whether comments are kept (`…xml-exc-c14n#WithComments`).
    pub(crate) comments: bool,
    /// The prefixes treated as inclusive canonicalization treats them
    /// (`InclusiveNamespaces PrefixList`), `""` for `#default`.
    pub(crate) inclusive: &'a [String],
    /// An element left out, wherever it is: the enveloped signature.
    pub(crate) without: Option<&'a Element>,
}

/// The canonical form of `element` and everything in it.
pub(crate) fn canonicalize(element: &Element, options: &Options<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    write_element(element, options, &BTreeMap::new(), &mut out);
    out
}

/// The namespace declarations an element writes: by prefix, each one it uses (or
/// `inclusive` names) whose meaning differs from what its output ancestors wrote.
fn declarations<'e>(
    element: &'e Element,
    options: &Options<'_>,
    rendered: &BTreeMap<&str, &str>,
) -> Vec<(&'e str, &'e str)> {
    let mut used: Vec<&str> = Vec::new();
    used.push(element.prefix.as_deref().unwrap_or(""));
    for attr in &element.attrs {
        if let Some(prefix) = attr.prefix.as_deref() {
            used.push(prefix);
        }
    }
    for prefix in options.inclusive {
        // An inclusive prefix is written only when it's in scope.
        if let Some((prefix, _)) = element.scope.get_key_value(prefix.as_str()) {
            used.push(prefix);
        }
    }
    let mut out: Vec<(&str, &str)> = Vec::new();
    for prefix in used {
        if prefix == "xml" || out.iter().any(|(p, _)| *p == prefix) {
            continue;
        }
        let Some((prefix, uri)) = element
            .scope
            .get_key_value(prefix)
            .map(|(p, u)| (p.as_str(), u.as_str()))
            .or_else(|| prefix.is_empty().then_some(("", "")))
        else {
            continue;
        };
        // No default namespace is the same as the empty one: `xmlns=""` is written only
        // to undo a default an output ancestor wrote.
        let before = rendered.get(prefix).copied().unwrap_or("");
        let fresh = !rendered.contains_key(prefix) && !uri.is_empty();
        if fresh || before != uri {
            out.push((prefix, uri));
        }
    }
    out.sort_unstable();
    out
}

fn write_element(
    element: &Element,
    options: &Options<'_>,
    rendered: &BTreeMap<&str, &str>,
    out: &mut Vec<u8>,
) {
    let name = qualified(element.prefix.as_deref(), &element.name);
    out.push(b'<');
    out.extend_from_slice(name.as_bytes());
    let declared = declarations(element, options, rendered);
    for (prefix, uri) in &declared {
        if prefix.is_empty() {
            out.extend_from_slice(b" xmlns=\"");
        } else {
            out.extend_from_slice(b" xmlns:");
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(b"=\"");
        }
        escape_attr(uri, out);
        out.push(b'"');
    }
    let mut attrs: Vec<_> = element.attrs.iter().collect();
    attrs.sort_unstable_by(|a, b| {
        (a.ns.as_deref().unwrap_or(""), &a.name).cmp(&(b.ns.as_deref().unwrap_or(""), &b.name))
    });
    for attr in attrs {
        out.push(b' ');
        out.extend_from_slice(qualified(attr.prefix.as_deref(), &attr.name).as_bytes());
        out.extend_from_slice(b"=\"");
        escape_attr(&attr.value, out);
        out.push(b'"');
    }
    out.push(b'>');
    let mut inner;
    let rendered = if declared.is_empty() {
        rendered
    } else {
        inner = rendered.clone();
        inner.extend(declared.iter().copied());
        &inner
    };
    for child in &element.children {
        match child {
            Node::Element(e) if options.without.is_some_and(|w| std::ptr::eq(w, e)) => {}
            Node::Element(e) => write_element(e, options, rendered, out),
            Node::Text(text) => escape_text(text, out),
            Node::Comment(text) if options.comments => {
                out.extend_from_slice(b"<!--");
                out.extend_from_slice(text.as_bytes());
                out.extend_from_slice(b"-->");
            }
            Node::Comment(_) => {}
            Node::Pi(target, data) => {
                out.extend_from_slice(b"<?");
                out.extend_from_slice(target.as_bytes());
                if !data.is_empty() {
                    out.push(b' ');
                    out.extend_from_slice(data.as_bytes());
                }
                out.extend_from_slice(b"?>");
            }
        }
    }
    out.extend_from_slice(b"</");
    out.extend_from_slice(name.as_bytes());
    out.push(b'>');
}

fn qualified(prefix: Option<&str>, name: &str) -> String {
    match prefix {
        Some(prefix) => format!("{prefix}:{name}"),
        None => name.to_owned(),
    }
}

fn escape_text(text: &str, out: &mut Vec<u8>) {
    for c in text.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
}

fn escape_attr(value: &str, out: &mut Vec<u8>) {
    for c in value.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;
    use crate::saml::xml;

    /// The first element named `name` in `root`, itself included.
    fn find<'a>(root: &'a Element, name: &str) -> &'a Element {
        root.descendants()
            .into_iter()
            .find(|e| e.name == name)
            .unwrap()
    }

    /// Documents, the element canonicalized (`root`, or the first `s`), its inclusive
    /// prefixes, whether comments are kept, and what lxml (libxml2) makes of them.
    #[test]
    fn subtrees_are_canonicalized_as_libxml2_does() {
        let cases: [(&str, &str, &[&str], bool, &str); 11] = [
            (
                r#"<a:r xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><a:s b:x="1" y="2"><t>x</t><b:u/></a:s></a:r>"#,
                "s",
                &[],
                false,
                r#"<a:s xmlns:a="urn:a" xmlns:b="urn:b" y="2" b:x="1"><t xmlns="urn:d">x</t><b:u></b:u></a:s>"#,
            ),
            (
                r#"<r xmlns="urn:d"><s xmlns=""><t xmlns="urn:e"/><u/></s></r>"#,
                "s",
                &[],
                false,
                r#"<s><t xmlns="urn:e"></t><u></u></s>"#,
            ),
            (
                r#"<r xmlns="urn:d"><s><t xmlns=""/></s></r>"#,
                "root",
                &[],
                false,
                r#"<r xmlns="urn:d"><s><t xmlns=""></t></s></r>"#,
            ),
            (
                r#"<r xmlns:p="urn:p" xmlns:q="urn:q"><p:s z="1" a="2" q:b="3" p:a="4"><!--c--><?pi  data?><![CDATA[a<b&c>]]>&#13;</p:s></r>"#,
                "s",
                &["q"],
                true,
                r#"<p:s xmlns:p="urn:p" xmlns:q="urn:q" a="2" z="1" p:a="4" q:b="3"><!--c--><?pi data?>a&lt;b&amp;c&gt;&#xD;</p:s>"#,
            ),
            (
                r#"<r xmlns:p="urn:p" xmlns:q="urn:q"><p:s><!--c--></p:s></r>"#,
                "s",
                &["q", "x"],
                false,
                r#"<p:s xmlns:p="urn:p" xmlns:q="urn:q"></p:s>"#,
            ),
            (
                r#"<r xml:lang="en" xmlns:p="urn:p"><s xml:space="preserve" a="&#9;&#10;&#13; &quot;&lt;&amp;&gt;">  sp  </s></r>"#,
                "s",
                &[],
                false,
                r#"<s a="&#x9;&#xA;&#xD; &quot;&lt;&amp;>" xml:space="preserve">  sp  </s>"#,
            ),
            (
                r#"<r xmlns:p="urn:p"><p:s><p:t xmlns:p="urn:p2"><p:u xmlns:p="urn:p"/></p:t></p:s></r>"#,
                "s",
                &[],
                false,
                r#"<p:s xmlns:p="urn:p"><p:t xmlns:p="urn:p2"><p:u xmlns:p="urn:p"></p:u></p:t></p:s>"#,
            ),
            (
                r#"<r xmlns="urn:d" xmlns:x="urn:x"><s><t/></s></r>"#,
                "s",
                &["", "x"],
                false,
                r#"<s xmlns="urn:d" xmlns:x="urn:x"><t></t></s>"#,
            ),
            (
                "<?xml version=\"1.0\"?>\n<r>\r\n<s a=\"x\r\ny\">l1\r\nl2\rl3</s></r>",
                "s",
                &[],
                false,
                r#"<s a="x y">l1
l2
l3</s>"#,
            ),
            (
                r#"<r xmlns:xml="http://www.w3.org/XML/1998/namespace"><s xml:lang="en"/></r>"#,
                "s",
                &["xml"],
                false,
                r#"<s xml:lang="en"></s>"#,
            ),
            ("<r><s><?pi?></s></r>", "s", &[], false, "<s><?pi?></s>"),
        ];
        for (document, apex, inclusive, comments, expected) in cases {
            let root = xml::parse(document).unwrap();
            let element = if apex == "root" {
                &root
            } else {
                find(&root, apex)
            };
            let inclusive: Vec<String> = inclusive.iter().map(|p| (*p).to_owned()).collect();
            let options = Options {
                comments,
                inclusive: &inclusive,
                without: None,
            };
            let out = canonicalize(element, &options);
            assert_eq!(String::from_utf8(out).unwrap(), expected, "{document}");
        }
    }

    #[test]
    fn an_enveloped_element_is_left_out() {
        let root = xml::parse(r#"<r xmlns:d="urn:d"><a/><d:sig><x/></d:sig><b/></r>"#).unwrap();
        let options = Options {
            without: Some(find(&root, "sig")),
            ..Options::default()
        };
        assert_eq!(canonicalize(&root, &options), b"<r><a></a><b></b></r>");
    }
}
