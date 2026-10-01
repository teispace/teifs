//! A strict XML tree for SAML: metadata documents and responses.
//!
//! Strict where XML is dangerous: a document type declaration (and so any entity but the
//! predefined ones and character references) is refused, as are text outside the root
//! element, deep nesting and duplicate attributes. Namespaces are resolved, and the
//! prefixes written are kept, since canonical XML writes them. Line ends and attribute
//! values are normalized as the XML specification says, so what's read is what a
//! canonicalizer and a signer saw.

use std::{collections::BTreeMap, sync::Arc};

use quick_xml::{
    Reader,
    escape::resolve_predefined_entity,
    events::{BytesStart, Event},
};

/// The XML namespace, which the `xml` prefix is bound to without a declaration.
pub(crate) const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
/// How deep elements may nest.
const MAX_DEPTH: usize = 64;

/// Why a document can't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct XmlError(pub(crate) String);

fn bad<T>(why: impl Into<String>) -> Result<T, XmlError> {
    Err(XmlError(why.into()))
}

/// The namespaces in scope: prefix (`""` for the default namespace) to URI.
pub(crate) type Scope = Arc<BTreeMap<String, String>>;

/// A node in an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Element(Element),
    Text(String),
    Comment(String),
    /// A processing instruction: its target and its content.
    Pi(String, String),
}

/// An attribute other than a namespace declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attr {
    pub(crate) prefix: Option<String>,
    pub(crate) name: String,
    /// Its namespace: none unless it has a prefix.
    pub(crate) ns: Option<String>,
    /// Its normalized value.
    pub(crate) value: String,
}

/// An element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Element {
    pub(crate) prefix: Option<String>,
    /// Its local name.
    pub(crate) name: String,
    pub(crate) ns: Option<String>,
    pub(crate) attrs: Vec<Attr>,
    /// The namespaces it declares, by prefix (`""` for the default).
    pub(crate) declared: Vec<(String, String)>,
    /// The namespaces in scope in it.
    pub(crate) scope: Scope,
    pub(crate) children: Vec<Node>,
}

impl Element {
    /// Whether it's `name` in namespace `ns`.
    pub(crate) fn is(&self, ns: &str, name: &str) -> bool {
        self.name == name && self.ns.as_deref() == Some(ns)
    }

    /// Its child elements.
    pub(crate) fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// Its child elements that are `name` in `ns`.
    pub(crate) fn all<'a>(
        &'a self,
        ns: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |e| e.is(ns, name))
    }

    /// Its only child element that's `name` in `ns`, if it has exactly one.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "for reading SAML responses, which come next")
    )]
    pub(crate) fn one(&self, ns: &str, name: &str) -> Result<Option<&Element>, XmlError> {
        let mut found = self.elements().filter(|e| e.is(ns, name));
        let first = found.next();
        if found.next().is_some() {
            return bad(format!(
                "<{name}> appears more than once in <{}>",
                self.name
            ));
        }
        Ok(first)
    }

    /// The value of its attribute `name` without a namespace.
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.ns.is_none() && a.name == name)
            .map(|a| a.value.as_str())
    }

    /// Its text: the text of its children, which mustn't be elements.
    pub(crate) fn text(&self) -> Result<String, XmlError> {
        let mut text = String::new();
        for node in &self.children {
            match node {
                Node::Text(t) => text.push_str(t),
                Node::Element(e) => {
                    return bad(format!("<{}> holds an element, <{}>", self.name, e.name));
                }
                Node::Comment(_) | Node::Pi(..) => {}
            }
        }
        Ok(text)
    }

    /// Every element in it, itself first, breadth first.
    pub(crate) fn descendants(&self) -> Vec<&Element> {
        let mut all = vec![self];
        let mut i = 0;
        while let Some(at) = all.get(i).copied() {
            all.extend(at.elements());
            i += 1;
        }
        all
    }
}

/// Reads `text`: a document whose root element is returned.
pub(crate) fn parse(text: &str) -> Result<Element, XmlError> {
    if text.starts_with('\u{feff}') {
        return bad("it starts with a byte order mark");
    }
    // Line ends are normalized before parsing, as the XML specification says.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut reader = Reader::from_str(&text);
    reader.config_mut().check_end_names = true;
    reader.config_mut().check_comments = true;
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    loop {
        let event = reader
            .read_event()
            .map_err(|e| XmlError(format!("it isn't well-formed XML: {e}")))?;
        match event {
            Event::Decl(_) if root.is_none() && stack.is_empty() => {}
            Event::Decl(_) => return bad("an XML declaration appears after the start"),
            Event::DocType(_) => return bad("it has a document type declaration"),
            Event::Start(_) | Event::Empty(_) if root.is_some() => {
                return bad("it has more than one root element");
            }
            Event::Start(start) => {
                if stack.len() >= MAX_DEPTH {
                    return bad(format!("its elements nest more than {MAX_DEPTH} deep"));
                }
                let scope = stack.last().map(|e| Arc::clone(&e.scope));
                stack.push(element(&start, scope)?);
            }
            Event::Empty(start) => {
                let scope = stack.last().map(|e| Arc::clone(&e.scope));
                let done = element(&start, scope)?;
                close(&mut stack, &mut root, done);
            }
            Event::End(_) => {
                let Some(done) = stack.pop() else {
                    return bad("an element ends that didn't start");
                };
                close(&mut stack, &mut root, done);
            }
            Event::Text(t) => text_node(&mut stack, &t.into_inner())?,
            Event::CData(t) => text_node(&mut stack, &t.into_inner())?,
            Event::GeneralRef(r) => {
                let resolved = if r.is_char_ref() {
                    match r.resolve_char_ref() {
                        Ok(Some(c)) => c.to_string(),
                        _ => return bad("it has a character reference to no character"),
                    }
                } else {
                    let name = r.into_inner();
                    match resolve_predefined_entity(&name) {
                        Some(c) => c.to_owned(),
                        None => return bad(format!("it refers to the entity &{name};")),
                    }
                };
                text_node(&mut stack, &resolved)?;
            }
            Event::Comment(c) => {
                if let Some(parent) = stack.last_mut() {
                    parent
                        .children
                        .push(Node::Comment(c.into_inner().into_owned()));
                }
            }
            Event::PI(pi) => {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Pi(
                        pi.target().to_owned(),
                        pi.content().trim_start().to_owned(),
                    ));
                }
            }
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return bad("it ends inside an element");
    }
    root.ok_or_else(|| XmlError("it has no root element".into()))
}

/// Adds text to the element being read; outside the root only white space may be.
fn text_node(stack: &mut [Element], text: &str) -> Result<(), XmlError> {
    let Some(parent) = stack.last_mut() else {
        if text.trim().is_empty() {
            return Ok(());
        }
        return bad("it has text outside its root element");
    };
    match parent.children.last_mut() {
        Some(Node::Text(t)) => t.push_str(text),
        _ => parent.children.push(Node::Text(text.to_owned())),
    }
    Ok(())
}

fn close(stack: &mut [Element], root: &mut Option<Element>, done: Element) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(Node::Element(done)),
        None => *root = Some(done),
    }
}

/// `prefix:name` split.
fn split(qname: &str) -> (Option<&str>, &str) {
    match qname.split_once(':') {
        Some((prefix, local)) => (Some(prefix), local),
        None => (None, qname),
    }
}

/// The namespace `prefix` names in `scope`.
fn resolve(
    scope: &BTreeMap<String, String>,
    prefix: Option<&str>,
) -> Result<Option<String>, XmlError> {
    match prefix {
        Some("xml") => Ok(Some(XML_NS.to_owned())),
        Some(p) => match scope.get(p) {
            Some(uri) => Ok(Some(uri.clone())),
            None => bad(format!("the prefix {p} isn't declared")),
        },
        None => Ok(scope.get("").cloned()),
    }
}

fn element(start: &BytesStart<'_>, parent: Option<Scope>) -> Result<Element, XmlError> {
    let qname = start.name();
    let (prefix, name) = split(qname.as_ref());
    let mut declared = Vec::new();
    let mut raw = Vec::new();
    let mut attributes = start.attributes();
    attributes.with_checks(true);
    for attr in attributes {
        let attr = attr.map_err(|e| XmlError(format!("an attribute is malformed: {e}")))?;
        let key = attr.key.as_ref().to_owned();
        let value = attr
            .normalized_value_with(
                quick_xml::XmlVersion::Implicit1_0,
                1,
                resolve_predefined_entity,
            )
            .map_err(|e| XmlError(format!("the attribute {key} is malformed: {e}")))?
            .into_owned();
        match split(&key) {
            (None, "xmlns") => declared.push((String::new(), value)),
            (Some("xmlns"), p) => {
                if value.is_empty() || p == "xmlns" || (p == "xml") != (value == XML_NS) {
                    return bad(format!("the namespace declaration {key} is invalid"));
                }
                declared.push((p.to_owned(), value));
            }
            _ => raw.push((key, value)),
        }
    }
    let scope = if declared.is_empty() {
        parent.unwrap_or_default()
    } else {
        let mut scope = parent.as_deref().cloned().unwrap_or_default();
        for (p, uri) in &declared {
            if p.is_empty() && uri.is_empty() {
                scope.remove("");
            } else {
                scope.insert(p.clone(), uri.clone());
            }
        }
        Arc::new(scope)
    };
    let mut attrs: Vec<Attr> = Vec::with_capacity(raw.len());
    for (key, value) in raw {
        let (p, local) = split(&key);
        let ns = match p {
            Some(_) => resolve(&scope, p)?,
            None => None,
        };
        if attrs.iter().any(|a| a.ns == ns && a.name == local) {
            return bad(format!("the attribute {key} appears twice"));
        }
        attrs.push(Attr {
            prefix: p.map(str::to_owned),
            name: local.to_owned(),
            ns,
            value,
        });
    }
    Ok(Element {
        prefix: prefix.map(str::to_owned),
        name: name.to_owned(),
        ns: resolve(&scope, prefix)?,
        attrs,
        declared,
        scope,
        children: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn namespaces_prefixes_and_values_are_read_as_written() {
        let doc = parse(
            "<?xml version=\"1.0\"?>\r\n<!-- before -->\n<md:A xmlns:md=\"urn:m\" xmlns=\"urn:d\" \
             id=\"a\tb\r\nc&#10;\">\r\n  <B x:y=\"1\" xmlns:x=\"urn:x\">t&amp;<![CDATA[<c>]]>&#x41;</B>\
             <C xmlns=\"\"/><?pi  data?><!--c--></md:A>",
        )
        .unwrap();
        assert!(doc.is("urn:m", "A"));
        assert_eq!(doc.prefix.as_deref(), Some("md"));
        assert_eq!(doc.attr("id"), Some("a b c\n"));
        assert_eq!(
            doc.declared,
            [
                ("md".to_owned(), "urn:m".to_owned()),
                (String::new(), "urn:d".to_owned())
            ]
        );
        let b = doc.one("urn:d", "B").unwrap().unwrap();
        assert_eq!(b.text().unwrap(), "t&<c>A");
        assert_eq!(b.attrs[0].ns.as_deref(), Some("urn:x"));
        assert_eq!(b.attrs[0].prefix.as_deref(), Some("x"));
        let c = doc.elements().nth(1).unwrap();
        assert_eq!((c.name.as_str(), c.ns.as_deref()), ("C", None));
        assert_eq!(doc.children[0], Node::Text("\n  ".into()));
        assert!(doc.children.contains(&Node::Pi("pi".into(), "data".into())));
        assert!(doc.children.contains(&Node::Comment("c".into())));
        assert_eq!(doc.descendants().len(), 3);
        assert!(doc.text().is_err());
    }

    #[test]
    fn dangerous_or_malformed_documents_are_refused() {
        let deep = format!("{}{}", "<a>".repeat(65), "</a>".repeat(65));
        for (doc, why) in [
            (
                "<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>",
                "document type declaration",
            ),
            ("<a>&x;</a>", "entity &x;"),
            ("<a/><b/>", "more than one root"),
            ("<a/>text", "text outside"),
            ("<a><b></a>", "well-formed"),
            ("<a>", "ends inside"),
            ("", "no root"),
            ("<p:a/>", "prefix p isn't declared"),
            ("<a x=\"1\" x=\"2\"/>", "malformed"),
            (
                "<a xmlns:p=\"urn:1\" xmlns:q=\"urn:1\" p:x=\"1\" q:x=\"2\"/>",
                "appears twice",
            ),
            ("<a xmlns:p=\"\"/>", "declaration xmlns:p is invalid"),
            ("<a xmlns:xml=\"urn:no\"/>", "is invalid"),
            ("\u{feff}<a/>", "byte order mark"),
            (deep.as_str(), "nest more than 64"),
        ] {
            let err = parse(doc).unwrap_err().0;
            assert!(err.contains(why), "{doc}: {err}");
        }
        let twice = parse("<a xmlns=\"urn:a\"><b/><b/></a>").unwrap();
        assert_eq!(twice.all("urn:a", "b").count(), 2);
        let err = twice.one("urn:a", "b").unwrap_err().0;
        assert!(err.contains("<b> appears more than once in <a>"), "{err}");
        assert_eq!(twice.one("urn:other", "b").unwrap(), None);
    }
}
