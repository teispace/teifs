//! Policy text that may hold variables: `home/${aws:username}/*`. A variable's value is
//! always literal (a `*` in a user name is not a wildcard), and `${*}`, `${?}` and
//! `${$}` write those characters literally. A variable the request has no single value
//! for resolves to its default (`${aws:PrincipalTag/team, 'shared'}`), or leaves the
//! whole text unresolved, which then matches nothing.

use std::borrow::Cow;

use crate::{
    Error,
    context::Context,
    key::Key,
    pattern::{self, Atom},
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Template {
    /// No variables: resolved once, when the policy is read.
    Static {
        /// The text, with `${*}` and friends written out.
        text: Box<str>,
        /// As a pattern.
        atoms: Box<[Atom]>,
    },
    Dynamic(Box<[Part]>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Part {
    /// Policy text: `*` and `?` in it are wildcards where the operator has them.
    Text(Box<str>),
    /// `${*}`, `${?}`, `${$}`.
    Literal(char),
    Var {
        key: Key,
        default: Option<Box<str>>,
    },
}

impl Template {
    /// Text without variables (policies before version 2012-10-17, and elements that
    /// don't take them).
    pub(crate) fn plain(text: &str) -> Self {
        Self::Static {
            text: text.into(),
            atoms: pattern::atoms(text).collect(),
        }
    }

    /// Text with `${…}` variables.
    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        let mut parts = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("${") {
            if start > 0 {
                parts.push(Part::Text(rest[..start].into()));
            }
            let after = &rest[start + 2..];
            let end = after
                .find('}')
                .ok_or_else(|| Error::new(format!("`{text}` has a `${{` without its `}}`")))?;
            parts.push(variable(&after[..end]).map_err(|e| e.within(format!("`{text}`")))?);
            rest = &after[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(Part::Text(rest.into()));
        }
        if parts.iter().any(|part| matches!(part, Part::Var { .. })) {
            return Ok(Self::Dynamic(parts.into()));
        }
        let mut text = String::new();
        let mut atoms = Vec::new();
        for part in &parts {
            match part {
                Part::Text(t) => {
                    text.push_str(t);
                    atoms.extend(pattern::atoms(t));
                }
                Part::Literal(c) => {
                    text.push(*c);
                    atoms.push(Atom::Char(*c));
                }
                Part::Var { .. } => unreachable!("static"),
            }
        }
        Ok(Self::Static {
            text: text.into(),
            atoms: atoms.into(),
        })
    }

    /// How many `:` come before the first variable, if there is one (ARNs take
    /// variables only in their resource part, after the fifth).
    pub(crate) fn colons_before_variable(&self) -> Option<usize> {
        let Self::Dynamic(parts) = self else {
            return None;
        };
        let mut colons = 0;
        for part in &**parts {
            match part {
                Part::Text(t) => colons += t.matches(':').count(),
                Part::Literal(c) => colons += usize::from(*c == ':'),
                Part::Var { .. } => return Some(colons),
            }
        }
        None
    }

    /// The literal text, for operators without wildcards.
    pub(crate) fn text<'a>(&'a self, context: &Context) -> Option<Cow<'a, str>> {
        match self {
            Self::Static { text, .. } => Some(Cow::Borrowed(text)),
            Self::Dynamic(parts) => {
                let mut text = String::new();
                for part in &**parts {
                    match part {
                        Part::Text(t) => text.push_str(t),
                        Part::Literal(c) => text.push(*c),
                        Part::Var { key, default } => {
                            text.push_str(&resolve(key, default.as_deref(), context)?);
                        }
                    }
                }
                Some(Cow::Owned(text))
            }
        }
    }

    /// The pattern, for `Like` operators and resources.
    pub(crate) fn atoms<'a>(&'a self, context: &Context) -> Option<Cow<'a, [Atom]>> {
        match self {
            Self::Static { atoms, .. } => Some(Cow::Borrowed(atoms)),
            Self::Dynamic(parts) => {
                let mut atoms = Vec::new();
                for part in &**parts {
                    match part {
                        Part::Text(t) => atoms.extend(pattern::atoms(t)),
                        Part::Literal(c) => atoms.push(Atom::Char(*c)),
                        Part::Var { key, default } => {
                            atoms.extend(pattern::literal(&resolve(
                                key,
                                default.as_deref(),
                                context,
                            )?));
                        }
                    }
                }
                Some(Cow::Owned(atoms))
            }
        }
    }
}

/// The inside of `${…}`.
fn variable(inner: &str) -> Result<Part, Error> {
    match inner {
        "*" => return Ok(Part::Literal('*')),
        "?" => return Ok(Part::Literal('?')),
        "$" => return Ok(Part::Literal('$')),
        _ => {}
    }
    let (name, default) = match inner.split_once(',') {
        Some((name, default)) => {
            let default = default.trim();
            let quoted = default
                .strip_prefix('\'')
                .and_then(|d| d.strip_suffix('\''))
                .filter(|d| !d.contains('\''))
                .ok_or_else(|| {
                    Error::new(format!(
                        "the default in `${{{inner}}}` goes in single quotes: `${{{}, 'value'}}`",
                        name_of(inner)
                    ))
                })?;
            (name.trim(), Some(quoted.into()))
        }
        None => (inner.trim(), None),
    };
    if name.is_empty() || name.contains(['$', '{']) {
        return Err(Error::new(format!(
            "`${{{inner}}}` doesn't name a variable"
        )));
    }
    Ok(Part::Var {
        key: Key::parse(name)?,
        default,
    })
}

fn name_of(inner: &str) -> &str {
    inner.split(',').next().unwrap_or(inner).trim()
}

/// A variable's value: the request's single value for the key, else the default.
fn resolve<'a>(key: &Key, default: Option<&'a str>, context: &'a Context) -> Option<Cow<'a, str>> {
    context
        .lookup(key)
        .single()
        .map(crate::context::Item::text)
        .or_else(|| default.map(Cow::Borrowed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{context::Principal, key::TagKind, value::Date};

    fn alice() -> Context {
        Context::new(
            Principal::user("123456789012", "/", "alice", "AIDAX"),
            Date::from_unix_seconds(0),
        )
        .with_tag(TagKind::Principal, "team", "blue")
    }

    fn text(template: &str, context: &Context) -> Option<String> {
        Template::parse(template)
            .unwrap()
            .text(context)
            .map(Cow::into_owned)
    }

    #[test]
    fn variables_take_the_requests_values() {
        let context = alice();
        assert_eq!(
            text("home/${aws:username}/", &context).as_deref(),
            Some("home/alice/")
        );
        assert_eq!(
            text("${aws:username}${aws:username}", &context).as_deref(),
            Some("alicealice")
        );
        assert_eq!(
            text("t-${aws:PrincipalTag/team}", &context).as_deref(),
            Some("t-blue")
        );
        assert_eq!(
            text("${ aws:username }", &context).as_deref(),
            Some("alice"),
            "spaces around the name"
        );
        // Missing: the default, else nothing at all.
        assert_eq!(
            text("${aws:PrincipalTag/dept, 'shared'}", &context).as_deref(),
            Some("shared")
        );
        assert_eq!(
            text("${aws:PrincipalTag/dept,'x y'}", &context).as_deref(),
            Some("x y")
        );
        assert_eq!(
            text("${aws:PrincipalTag/dept, ''}/a", &context).as_deref(),
            Some("/a")
        );
        assert_eq!(text("x/${aws:PrincipalTag/dept}", &context), None);
        assert_eq!(
            text("${aws:TagKeys}", &context),
            None,
            "multivalued keys aren't variables"
        );
        assert_eq!(text("${s3:unknownthing}", &context), None);
    }

    #[test]
    fn escapes_and_literal_values() {
        let context = alice();
        let escaped = Template::parse("a${*}b${?}c${$}").unwrap();
        assert!(matches!(escaped, Template::Static { .. }));
        assert_eq!(escaped.text(&context).as_deref(), Some("a*b?c$"));
        let atoms = escaped.atoms(&context).unwrap();
        assert!(pattern::matches(&atoms, "a*b?c$", false));
        assert!(
            !pattern::matches(&atoms, "aXbYc$", false),
            "escaped, not wildcards"
        );
        // `$` alone and `{…}` without `$` are plain text.
        assert_eq!(text("cost$ {x}", &context).as_deref(), Some("cost$ {x}"));

        // A value with `*` in it is literal where the policy's own `*` is a wildcard.
        let starry = Context::new(
            Principal::user("123456789012", "/", "a*", "AIDAY"),
            Date::from_unix_seconds(0),
        );
        let home = Template::parse("home/${aws:username}/*").unwrap();
        let atoms = home.atoms(&starry).unwrap();
        assert!(pattern::matches(&atoms, "home/a*/x", false));
        assert!(!pattern::matches(&atoms, "home/abc/x", false));
    }

    #[test]
    fn malformed_variables_are_refused() {
        for bad in [
            "${aws:username",
            "${}",
            "${ }",
            "${aws:username, default}",
            "${aws:username, 'a'b'}",
            "${aws:username, \"x\"}",
            "${${aws:username}}",
            "${aws:RequestTag/}",
        ] {
            assert!(Template::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn plain_text_keeps_dollar_braces() {
        let plain = Template::plain("${aws:username}*");
        assert_eq!(plain.text(&alice()).as_deref(), Some("${aws:username}*"));
        assert_eq!(plain.colons_before_variable(), None);
    }

    #[test]
    fn counts_colons_before_the_first_variable() {
        let arn = Template::parse("arn:aws:s3:::b/${aws:username}:x").unwrap();
        assert_eq!(arn.colons_before_variable(), Some(5));
        let early = Template::parse("arn:aws:s3:${aws:username}::b").unwrap();
        assert_eq!(early.colons_before_variable(), Some(3));
    }
}
