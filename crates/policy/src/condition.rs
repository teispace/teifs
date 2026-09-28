//! The `Condition` element: every operator AWS defines, `…IfExists`, and the
//! `ForAllValues:` / `ForAnyValue:` set operators.
//!
//! How a condition holds, for a key the request has values `R` for and the policy lists
//! values `P` for (`hit(r)`: `r` matches some value in `P`):
//!
//! | operator            | positive (`StringLike`)  | negated (`StringNotLike`)   |
//! |---------------------|--------------------------|-----------------------------|
//! | plain               | some `r` hits            | no `r` hits                 |
//! | `ForAnyValue:`      | some `r` hits            | some `r` doesn't hit        |
//! | `ForAllValues:`     | every `r` hits           | no `r` hits                 |
//!
//! With `R` empty (the key is absent) these give: plain positive false, plain negated
//! true, `ForAnyValue:` false, `ForAllValues:` true. `…IfExists` makes any operator true
//! when the key is absent. `Null` asks only whether the key is absent.

use std::cmp::Ordering;

use base64::Engine as _;

use crate::{
    Error, arn,
    context::{Context, Item, parse_bool},
    json::Json,
    key::Key,
    pattern,
    policy::Version,
    template::Template,
    value::{Cidr, Date, Number},
};

/// One key's test: `"StringLike": {"s3:prefix": ["home/", "shared/"]}`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Condition {
    set: Option<Set>,
    negated: bool,
    if_exists: bool,
    key: Key,
    expected: Expected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Set {
    AnyValue,
    AllValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringMode {
    Exact,
    IgnoreCase,
    Like,
}

/// The policy's values, parsed for the operator.
#[derive(Debug, Clone, PartialEq)]
enum Expected {
    Strings(StringMode, Box<[Template]>),
    Numbers(Ordering, bool, Box<[Number]>),
    Dates(Ordering, bool, Box<[Date]>),
    Bools(Box<[Template]>),
    Binary(Box<[Box<[u8]>]>),
    Cidrs(Box<[Cidr]>),
    Arns(Box<[Template]>),
    /// `Null`: `true` means "the key is absent".
    Null(bool),
}

/// The base operators: name, negated, and what they compare.
#[derive(Clone, Copy)]
enum Base {
    String(StringMode),
    /// A comparison: the ordering wanted, and whether equal also passes.
    Numeric(Ordering, bool),
    Date(Ordering, bool),
    Bool,
    Binary,
    Ip,
    Arn,
    Null,
}

const OPERATORS: &[(&str, bool, Base)] = &[
    ("StringEquals", false, Base::String(StringMode::Exact)),
    ("StringNotEquals", true, Base::String(StringMode::Exact)),
    (
        "StringEqualsIgnoreCase",
        false,
        Base::String(StringMode::IgnoreCase),
    ),
    (
        "StringNotEqualsIgnoreCase",
        true,
        Base::String(StringMode::IgnoreCase),
    ),
    ("StringLike", false, Base::String(StringMode::Like)),
    ("StringNotLike", true, Base::String(StringMode::Like)),
    ("NumericEquals", false, Base::Numeric(Ordering::Equal, true)),
    (
        "NumericNotEquals",
        true,
        Base::Numeric(Ordering::Equal, true),
    ),
    (
        "NumericLessThan",
        false,
        Base::Numeric(Ordering::Less, false),
    ),
    (
        "NumericLessThanEquals",
        false,
        Base::Numeric(Ordering::Less, true),
    ),
    (
        "NumericGreaterThan",
        false,
        Base::Numeric(Ordering::Greater, false),
    ),
    (
        "NumericGreaterThanEquals",
        false,
        Base::Numeric(Ordering::Greater, true),
    ),
    ("DateEquals", false, Base::Date(Ordering::Equal, true)),
    ("DateNotEquals", true, Base::Date(Ordering::Equal, true)),
    ("DateLessThan", false, Base::Date(Ordering::Less, false)),
    (
        "DateLessThanEquals",
        false,
        Base::Date(Ordering::Less, true),
    ),
    (
        "DateGreaterThan",
        false,
        Base::Date(Ordering::Greater, false),
    ),
    (
        "DateGreaterThanEquals",
        false,
        Base::Date(Ordering::Greater, true),
    ),
    ("Bool", false, Base::Bool),
    ("BinaryEquals", false, Base::Binary),
    ("IpAddress", false, Base::Ip),
    ("NotIpAddress", true, Base::Ip),
    ("ArnEquals", false, Base::Arn),
    ("ArnLike", false, Base::Arn),
    ("ArnNotEquals", true, Base::Arn),
    ("ArnNotLike", true, Base::Arn),
    ("Null", false, Base::Null),
];

/// Reads a `Condition` element: operator → key → value or list of values.
pub(crate) fn parse(json: &Json, version: Version) -> Result<Vec<Condition>, Error> {
    let Json::Object(operators) = json else {
        return Err(Error::new(format!(
            "Condition must be an object, not {}",
            json.kind()
        )));
    };
    let mut conditions = Vec::new();
    for (operator, keys) in operators {
        let Json::Object(keys) = keys else {
            return Err(Error::new(format!(
                "{operator} must be an object of condition keys, not {}",
                keys.kind()
            )));
        };
        if keys.is_empty() {
            return Err(Error::new(format!("{operator} names no condition keys")));
        }
        for (key, values) in keys {
            conditions.push(
                Condition::parse(operator, key, values, version)
                    .map_err(|e| e.within(format!("{operator} {key}")))?,
            );
        }
    }
    Ok(conditions)
}

impl Condition {
    fn parse(operator: &str, key: &str, values: &Json, version: Version) -> Result<Self, Error> {
        let unknown = || Error::new(format!("`{operator}` isn't a condition operator"));
        let (set, name) = if let Some(name) = operator.strip_prefix("ForAnyValue:") {
            (Some(Set::AnyValue), name)
        } else if let Some(name) = operator.strip_prefix("ForAllValues:") {
            (Some(Set::AllValues), name)
        } else {
            (None, operator)
        };
        let (name, if_exists) = match name.strip_suffix("IfExists") {
            Some(name) => (name, true),
            None => (name, false),
        };
        let &(_, negated, base) = OPERATORS
            .iter()
            .find(|(known, _, _)| *known == name)
            .ok_or_else(unknown)?;
        if matches!(base, Base::Null) && (set.is_some() || if_exists) {
            return Err(unknown());
        }
        let texts = texts(values)?;
        // Variables only where AWS allows them, and only from version 2012-10-17.
        let template = |text: &str| match version {
            Version::V2012_10_17 => Template::parse(text),
            Version::V2008_10_17 => Ok(Template::plain(text)),
        };
        let templates = || {
            texts
                .iter()
                .map(|t| template(t))
                .collect::<Result<Box<[Template]>, Error>>()
        };
        let expected = match base {
            Base::String(mode) => Expected::Strings(mode, templates()?),
            Base::Arn => Expected::Arns(templates()?),
            Base::Bool => {
                // A variable is checked when resolved; plain text must be a boolean now.
                let templates = templates()?;
                for (text, template) in texts.iter().zip(&templates) {
                    if matches!(template, Template::Static { .. }) && parse_bool(text).is_none() {
                        return Err(Error::new(format!("`{text}` isn't true or false")));
                    }
                }
                Expected::Bools(templates)
            }
            Base::Numeric(order, or_equal) => {
                Expected::Numbers(order, or_equal, all(&texts, Number::parse, "a number")?)
            }
            Base::Date(order, or_equal) => Expected::Dates(
                order,
                or_equal,
                all(
                    &texts,
                    Date::parse,
                    "a date (ISO 8601, or seconds since 1970)",
                )?,
            ),
            Base::Binary => Expected::Binary(all(
                &texts,
                |t| {
                    base64::engine::general_purpose::STANDARD
                        .decode(t)
                        .ok()
                        .map(Vec::into_boxed_slice)
                },
                "base64",
            )?),
            Base::Ip => Expected::Cidrs(all(&texts, Cidr::parse, "an IP address or CIDR block")?),
            Base::Null => match texts.as_slice() {
                [one] => Expected::Null(
                    parse_bool(one)
                        .ok_or_else(|| Error::new(format!("`{one}` isn't true or false")))?,
                ),
                _ => return Err(Error::new("Null takes one value, true or false")),
            },
        };
        Ok(Self {
            set,
            negated,
            if_exists,
            key: Key::parse(key)?,
            expected,
        })
    }

    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// Whether the condition holds for the request.
    pub(crate) fn holds(&self, context: &Context) -> bool {
        let values = context.lookup(&self.key);
        if let Expected::Null(absent) = self.expected {
            return values.is_empty() == absent;
        }
        if self.if_exists && values.is_empty() {
            return true;
        }
        let hit = |item: Item<'_>| self.expected.any_matches(item, context);
        match (self.set, self.negated) {
            (None, negated) => values.iter().any(hit) != negated,
            (Some(Set::AnyValue), false) => values.iter().any(hit),
            (Some(Set::AnyValue), true) => values.iter().any(|item| !hit(item)),
            (Some(Set::AllValues), false) => values.iter().all(hit),
            (Some(Set::AllValues), true) => values.iter().all(|item| !hit(item)),
        }
    }
}

impl Expected {
    /// Whether one request value matches any of the policy's values. A policy value
    /// whose variable has no value matches nothing.
    fn any_matches(&self, item: Item<'_>, context: &Context) -> bool {
        match self {
            Self::Strings(mode, templates) => {
                let text = item.text();
                templates.iter().any(|template| match mode {
                    StringMode::Exact => template.text(context).is_some_and(|want| want == text),
                    StringMode::IgnoreCase => template.text(context).is_some_and(|want| {
                        want.chars()
                            .flat_map(char::to_lowercase)
                            .eq(text.chars().flat_map(char::to_lowercase))
                    }),
                    StringMode::Like => template
                        .atoms(context)
                        .is_some_and(|atoms| pattern::matches(&atoms, &text, false)),
                })
            }
            Self::Arns(templates) => {
                let text = item.text();
                templates.iter().any(|template| {
                    template.atoms(context).is_some_and(|atoms| {
                        // A lone `*` matches only values that are ARNs here.
                        text.starts_with("arn:") && arn::matches(&atoms, &text)
                    })
                })
            }
            Self::Numbers(order, or_equal, numbers) => item.number().is_some_and(|n| {
                numbers
                    .iter()
                    .any(|want| compares(n.cmp(want), *order, *or_equal))
            }),
            Self::Dates(order, or_equal, dates) => item.date().is_some_and(|d| {
                dates
                    .iter()
                    .any(|want| compares(d.cmp(want), *order, *or_equal))
            }),
            Self::Bools(templates) => item.bool().is_some_and(|b| {
                templates
                    .iter()
                    .any(|template| template.text(context).and_then(|t| parse_bool(&t)) == Some(b))
            }),
            Self::Binary(blobs) => match item {
                Item::Str(text) => blobs.iter().any(|blob| **blob == *text.as_bytes()),
                _ => false,
            },
            Self::Cidrs(blocks) => item
                .ip()
                .is_some_and(|ip| blocks.iter().any(|block| block.contains(ip))),
            Self::Null(_) => false,
        }
    }
}

/// Whether `found` (request value against policy value) is what the operator wants:
/// `order`, or also equal when `or_equal`.
fn compares(found: Ordering, order: Ordering, or_equal: bool) -> bool {
    found == order || (or_equal && found == Ordering::Equal)
}

/// Every text parsed by `parse`, or which one isn't `what`.
fn all<T>(
    texts: &[String],
    parse: impl Fn(&str) -> Option<T>,
    what: &str,
) -> Result<Box<[T]>, Error> {
    texts
        .iter()
        .map(|text| parse(text).ok_or_else(|| Error::new(format!("`{text}` isn't {what}"))))
        .collect()
}

/// A condition's values as text: a string, number or boolean, or a non-empty list of them.
fn texts(json: &Json) -> Result<Vec<String>, Error> {
    let one = |json: &Json| match json {
        Json::String(s) => Ok(s.clone()),
        Json::Number(n) => Ok(n.to_string()),
        Json::Bool(b) => Ok(b.to_string()),
        other => Err(Error::new(format!(
            "a condition value is a string, number or boolean, not {}",
            other.kind()
        ))),
    };
    match json {
        Json::Array(items) if items.is_empty() => Err(Error::new("an empty list of values")),
        Json::Array(items) => items.iter().map(one).collect(),
        other => one(other).map(|text| vec![text]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        context::Principal,
        key::{S3Key, TagKind},
    };

    fn context() -> Context {
        Context::new(
            Principal::user("123456789012", "/", "alice", "AIDAX"),
            Date::parse("2026-09-29T12:00:00Z").unwrap(),
        )
        .with_source_ip("203.0.113.9".parse().unwrap())
        .with_secure_transport(true)
        .with(S3Key::Prefix, "home/alice/")
        .with(S3Key::MaxKeys, 100)
        .with(S3Key::TlsVersion, Number::parse("1.2").unwrap())
        .with_tag(TagKind::Request, "team", "blue")
        .with_tag(TagKind::Request, "cost", "7")
    }

    /// Whether `{"OPERATOR": {"KEY": VALUES}}` holds for [`context`].
    fn holds(operator: &str, key: &str, values: &str) -> bool {
        holds_in(&context(), operator, key, values)
    }

    fn holds_in(context: &Context, operator: &str, key: &str, values: &str) -> bool {
        let json = Json::parse(&format!(r#"{{"{operator}": {{"{key}": {values}}}}}"#)).unwrap();
        let conditions = parse(&json, Version::V2012_10_17).unwrap();
        conditions.iter().all(|c| c.holds(context))
    }

    fn refused(operator: &str, key: &str, values: &str) -> String {
        let json = Json::parse(&format!(r#"{{"{operator}": {{"{key}": {values}}}}}"#)).unwrap();
        parse(&json, Version::V2012_10_17).unwrap_err().to_string()
    }

    #[test]
    fn string_operators() {
        assert!(holds("StringEquals", "s3:prefix", r#""home/alice/""#));
        assert!(!holds("StringEquals", "s3:prefix", r#""HOME/alice/""#));
        assert!(
            holds("StringEquals", "s3:prefix", r#"["x", "home/alice/"]"#),
            "values are ORed"
        );
        assert!(holds("StringNotEquals", "s3:prefix", r#"["x", "y"]"#));
        assert!(!holds(
            "StringNotEquals",
            "s3:prefix",
            r#"["x", "home/alice/"]"#
        ));
        assert!(holds(
            "StringEqualsIgnoreCase",
            "s3:prefix",
            r#""HOME/Alice/""#
        ));
        assert!(!holds(
            "StringNotEqualsIgnoreCase",
            "s3:prefix",
            r#""HOME/Alice/""#
        ));
        assert!(holds("StringLike", "s3:prefix", r#""home/*""#));
        assert!(holds("StringLike", "s3:prefix", r#""home/?lice/""#));
        assert!(
            !holds("StringEquals", "s3:prefix", r#""home/*""#),
            "no wildcards in Equals"
        );
        assert!(holds("StringNotLike", "s3:prefix", r#""shared/*""#));
        assert!(holds(
            "StringLike",
            "s3:prefix",
            r#""home/${aws:username}/""#
        ));
        assert!(holds("StringEquals", "aws:PrincipalType", r#""User""#));
        // Other types compare as their text.
        assert!(holds("StringEquals", "s3:max-keys", r#""100""#));
        assert!(holds("StringEquals", "aws:SecureTransport", r#""true""#));
    }

    #[test]
    fn a_missing_key_fails_positive_operators_and_passes_negated_ones() {
        for (operator, expected) in [
            ("StringEquals", false),
            ("StringNotEquals", true),
            ("StringLike", false),
            ("StringNotLike", true),
            ("StringEqualsIgnoreCase", false),
            ("StringNotEqualsIgnoreCase", true),
            ("StringEqualsIfExists", true),
            ("StringNotEqualsIfExists", true),
        ] {
            assert_eq!(
                holds(operator, "s3:delimiter", r#""/""#),
                expected,
                "{operator}"
            );
        }
        assert!(!holds("NumericLessThan", "s3:signatureAge", "10"));
        assert!(holds("NumericNotEquals", "s3:signatureAge", "10"));
        assert!(holds("NumericLessThanIfExists", "s3:signatureAge", "10"));
        assert!(!holds(
            "DateGreaterThan",
            "aws:TokenIssueTime",
            r#""2020-01-01""#
        ));
        assert!(holds(
            "DateNotEquals",
            "aws:TokenIssueTime",
            r#""2020-01-01""#
        ));
        assert!(!holds("IpAddress", "aws:VpcSourceIp", r#""10.0.0.0/8""#));
        assert!(holds("NotIpAddress", "aws:VpcSourceIp", r#""10.0.0.0/8""#));
        assert!(!holds("ArnLike", "aws:SourceArn", r#""arn:*""#));
        assert!(holds("ArnNotLike", "aws:SourceArn", r#""arn:*""#));
        assert!(!holds("Bool", "aws:MultiFactorAuthPresent", r#""true""#));
        assert!(holds(
            "BoolIfExists",
            "aws:MultiFactorAuthPresent",
            r#""true""#
        ));
        assert!(!holds("BinaryEquals", "s3:x-amz-acl", r#""cHJpdmF0ZQ==""#));
    }

    #[test]
    fn numeric_date_bool_binary_ip_arn() {
        assert!(holds("NumericEquals", "s3:max-keys", "100"));
        assert!(holds("NumericEquals", "s3:max-keys", r#""100.0""#));
        assert!(holds("NumericLessThanEquals", "s3:max-keys", "100"));
        assert!(!holds("NumericLessThan", "s3:max-keys", "100"));
        assert!(holds("NumericGreaterThan", "s3:max-keys", "99.5"));
        assert!(!holds("NumericGreaterThanEquals", "s3:max-keys", "101"));
        assert!(holds("NumericLessThan", "s3:TlsVersion", "1.3"));
        assert!(!holds("NumericLessThan", "s3:TlsVersion", "1.2"));
        assert!(holds("NumericNotEquals", "s3:max-keys", "[1, 2]"));

        assert!(holds("DateLessThan", "aws:CurrentTime", r#""2026-09-30""#));
        assert!(holds(
            "DateGreaterThan",
            "aws:CurrentTime",
            r#""2026-09-29T11:59:59Z""#
        ));
        assert!(holds(
            "DateEquals",
            "aws:CurrentTime",
            r#""2026-09-29T14:00:00+02:00""#
        ));
        assert!(
            holds("DateLessThan", "aws:CurrentTime", "1900000000"),
            "epoch seconds"
        );
        assert!(holds("DateLessThan", "aws:EpochTime", r#""2027-01-01""#));
        assert!(holds("NumericGreaterThan", "aws:EpochTime", "1700000000"));

        assert!(holds("Bool", "aws:SecureTransport", r#""true""#));
        assert!(
            holds("Bool", "aws:SecureTransport", "true"),
            "a JSON boolean"
        );
        assert!(!holds("Bool", "aws:SecureTransport", r#""false""#));
        assert!(holds("Bool", "aws:ViaAWSService", r#""false""#));

        let acl = context().with(S3Key::Acl, "private");
        assert!(holds_in(
            &acl,
            "BinaryEquals",
            "s3:x-amz-acl",
            r#""cHJpdmF0ZQ==""#
        ));
        assert!(!holds_in(
            &acl,
            "BinaryEquals",
            "s3:x-amz-acl",
            r#""cHVibGlj""#
        ));

        assert!(holds("IpAddress", "aws:SourceIp", r#""203.0.113.0/24""#));
        assert!(holds(
            "IpAddress",
            "aws:SourceIp",
            r#"["10.0.0.0/8", "203.0.113.9"]"#
        ));
        assert!(!holds(
            "NotIpAddress",
            "aws:SourceIp",
            r#""203.0.113.0/24""#
        ));
        assert!(holds("NotIpAddress", "aws:SourceIp", r#""2001:db8::/32""#));

        for operator in ["ArnLike", "ArnEquals"] {
            assert!(holds(
                operator,
                "aws:PrincipalArn",
                r#""arn:aws:iam::*:user/alice""#
            ));
            assert!(!holds(
                operator,
                "aws:PrincipalArn",
                r#""arn:aws:iam::*:user/bob""#
            ));
        }
        assert!(holds(
            "ArnNotEquals",
            "aws:PrincipalArn",
            r#""arn:aws:iam::*:user/bob""#
        ));
        assert!(!holds("ArnLike", "s3:prefix", r#""*""#), "not an ARN");
    }

    #[test]
    fn set_operators_on_multivalued_keys() {
        // The request's aws:TagKeys are ["team", "cost"].
        assert!(holds(
            "ForAllValues:StringEquals",
            "aws:TagKeys",
            r#"["team", "cost", "owner"]"#
        ));
        assert!(!holds(
            "ForAllValues:StringEquals",
            "aws:TagKeys",
            r#"["team"]"#
        ));
        assert!(holds(
            "ForAnyValue:StringEquals",
            "aws:TagKeys",
            r#"["team"]"#
        ));
        assert!(!holds(
            "ForAnyValue:StringEquals",
            "aws:TagKeys",
            r#"["owner"]"#
        ));
        // Negated: ForAllValues = none of them; ForAnyValue = at least one isn't.
        assert!(holds(
            "ForAllValues:StringNotEquals",
            "aws:TagKeys",
            r#"["owner"]"#
        ));
        assert!(!holds(
            "ForAllValues:StringNotEquals",
            "aws:TagKeys",
            r#"["team"]"#
        ));
        assert!(holds(
            "ForAnyValue:StringNotEquals",
            "aws:TagKeys",
            r#"["team"]"#
        ));
        assert!(!holds(
            "ForAnyValue:StringNotEquals",
            "aws:TagKeys",
            r#"["team", "cost"]"#
        ));
        assert!(holds("ForAnyValue:StringLike", "aws:TagKeys", r#""c*""#));
        assert!(!holds("ForAllValues:StringLike", "aws:TagKeys", r#""c*""#));
        // Plain operators on a multivalued key: some value matches.
        assert!(holds("StringEquals", "aws:TagKeys", r#""cost""#));
        assert!(!holds("StringNotEquals", "aws:TagKeys", r#""cost""#));

        // With no values: ForAllValues holds (the known pitfall), ForAnyValue doesn't.
        let bare = Context::new(Principal::anonymous(), Date::from_unix_seconds(0));
        for (operator, expected) in [
            ("ForAllValues:StringEquals", true),
            ("ForAllValues:StringNotEquals", true),
            ("ForAnyValue:StringEquals", false),
            ("ForAnyValue:StringNotEquals", false),
            ("ForAnyValue:StringEqualsIfExists", true),
        ] {
            assert_eq!(
                holds_in(&bare, operator, "aws:TagKeys", r#""team""#),
                expected,
                "{operator}"
            );
        }
    }

    #[test]
    fn null_asks_whether_the_key_is_absent() {
        assert!(holds("Null", "s3:delimiter", r#""true""#));
        assert!(!holds("Null", "s3:prefix", r#""true""#));
        assert!(holds("Null", "s3:prefix", "false"));
        assert!(holds("Null", "aws:TagKeys", r#""false""#));
        let bare = Context::new(Principal::anonymous(), Date::from_unix_seconds(0));
        assert!(
            holds_in(&bare, "Null", "aws:TagKeys", r#""true""#),
            "an empty list is absent"
        );
    }

    #[test]
    fn unresolved_variables_match_nothing() {
        assert!(!holds(
            "StringLike",
            "s3:prefix",
            r#""home/${aws:PrincipalTag/x}/*""#
        ));
        assert!(holds(
            "StringNotLike",
            "s3:prefix",
            r#""home/${aws:PrincipalTag/x}/*""#
        ));
        assert!(holds(
            "StringLike",
            "s3:prefix",
            r#""home/${aws:PrincipalTag/x, 'alice'}/*""#
        ));
        // Bool takes variables too: the default, or the key's value.
        assert!(holds(
            "Bool",
            "aws:SecureTransport",
            r#""${aws:PrincipalTag/x, 'true'}""#
        ));
        assert!(!holds(
            "Bool",
            "aws:SecureTransport",
            r#""${aws:ViaAWSService}""#
        ));
    }

    #[test]
    fn variables_only_from_2012_10_17() {
        let json =
            Json::parse(r#"{"StringEquals": {"s3:prefix": "home/${aws:username}/"}}"#).unwrap();
        let old = parse(&json, Version::V2008_10_17).unwrap();
        let mine = context().with(S3Key::Prefix, "home/${aws:username}/");
        assert!(old[0].holds(&mine), "literal text before 2012-10-17");
        assert!(!old[0].holds(&context()));
    }

    #[test]
    fn invalid_conditions_are_refused() {
        assert!(
            refused("StringEqualz", "s3:prefix", r#""x""#).contains("isn't a condition operator")
        );
        assert!(
            refused("stringequals", "s3:prefix", r#""x""#).contains("isn't a condition operator")
        );
        assert!(refused("ForAllValues:Null", "s3:prefix", r#""true""#).contains("operator"));
        assert!(refused("NullIfExists", "s3:prefix", r#""true""#).contains("operator"));
        assert!(refused("ForSomeValues:StringEquals", "s3:prefix", r#""x""#).contains("operator"));
        assert!(refused("NumericEquals", "s3:max-keys", r#""ten""#).contains("isn't a number"));
        assert!(
            refused("NumericEquals", "s3:max-keys", r#""${aws:username}""#)
                .contains("isn't a number")
        );
        assert!(refused("DateLessThan", "aws:CurrentTime", r#""soon""#).contains("isn't a date"));
        assert!(refused("IpAddress", "aws:SourceIp", r#""10.0.0.0/33""#).contains("IP address"));
        assert!(refused("BinaryEquals", "s3:x-amz-acl", r#""!!""#).contains("base64"));
        assert!(refused("Bool", "aws:SecureTransport", r#""yes""#).contains("true or false"));
        assert!(refused("Null", "s3:prefix", r#"["true", "false"]"#).contains("one value"));
        assert!(refused("StringEquals", "s3:prefix", "[]").contains("empty"));
        assert!(refused("StringEquals", "s3:prefix", "null").contains("not null"));
        assert!(refused("StringEquals", "s3:prefix", r#"{"a": 1}"#).contains("an object"));
        assert!(refused("StringEquals", "bad key", r#""x""#).contains("isn't a condition key"));
        assert!(refused("StringLike", "s3:prefix", r#""${aws:username""#).contains("without its"));
        let json = Json::parse(r#"{"StringEquals": {}}"#).unwrap();
        assert!(parse(&json, Version::V2012_10_17).is_err());
        let json = Json::parse(r#"{"StringEquals": "x"}"#).unwrap();
        assert!(parse(&json, Version::V2012_10_17).is_err());
    }

    #[test]
    fn keys_and_operators_are_anded() {
        let json = Json::parse(
            r#"{"StringLike": {"s3:prefix": "home/*", "aws:PrincipalType": "User"},
                "Bool": {"aws:SecureTransport": "true"}}"#,
        )
        .unwrap();
        let conditions = parse(&json, Version::V2012_10_17).unwrap();
        assert_eq!(conditions.len(), 3);
        assert!(conditions.iter().all(|c| c.holds(&context())));
        let plain = context().with_secure_transport(false);
        assert!(!conditions.iter().all(|c| c.holds(&plain)));
    }
}
