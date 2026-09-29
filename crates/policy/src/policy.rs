//! Policy documents: reading them strictly, and whether a statement applies to a request.
//!
//! Strict means: unknown elements, repeated keys, a wrong `Version`, an empty list,
//! a malformed action, ARN, principal or condition are all refused when the policy is
//! stored, never skipped when it's evaluated. A policy TeiFS accepts means what it says.

use crate::{
    ACTIONS, Error,
    condition::{self, Condition},
    context::Principal,
    evaluate::Request,
    json::Json,
    key::Key,
    pattern::{self, Atom},
    template::Template,
};

/// The policy language version (`Version`). Variables (`${aws:username}`) exist only
/// in 2012-10-17; a policy without `Version` is 2008-10-17, as on AWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// `2008-10-17`: `${…}` is plain text.
    V2008_10_17,
    /// `2012-10-17`: the current language.
    V2012_10_17,
}

/// Where a policy is attached, which decides whether it names principals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// On a user, group or role, or used as a permissions boundary or session policy:
    /// it applies to its holder and names no `Principal`.
    Identity,
    /// On a resource (a bucket policy): every statement names a `Principal` or
    /// `NotPrincipal`.
    Resource,
}

/// A parsed policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    version: Version,
    id: Option<String>,
    kind: Kind,
    statements: Box<[Statement]>,
}

#[derive(Debug, Clone, PartialEq)]
struct Statement {
    sid: Option<String>,
    effect: Effect,
    principal: Option<Principals>,
    actions: Actions,
    resources: Resources,
    conditions: Box<[Condition]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Allow,
    Deny,
}

/// `Principal` (or, `negated`, `NotPrincipal`).
#[derive(Debug, Clone, PartialEq)]
struct Principals {
    negated: bool,
    entries: Box<[PrincipalEntry]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrincipalEntry {
    /// `"*"` or `{"AWS": "*"}`: everyone, anonymous included.
    Anyone,
    /// An account: `123456789012` or `arn:aws:iam::123456789012:root`.
    Account(Box<str>),
    /// A user, role or session ARN.
    Arn(Box<str>),
    /// `{"CanonicalUser": "…"}`.
    Canonical(Box<str>),
    /// An AWS service or identity provider: never a TeiFS caller.
    Never,
}

/// `Action` (or, `negated`, `NotAction`).
#[derive(Debug, Clone, PartialEq)]
struct Actions {
    negated: bool,
    patterns: Box<[Box<[Atom]>]>,
}

/// `Resource` (or, `negated`, `NotResource`).
#[derive(Debug, Clone, PartialEq)]
struct Resources {
    negated: bool,
    templates: Box<[Template]>,
}

/// How directly a resource policy's `Allow` names the principal: which of the
/// principal's other policies still have to agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Grant {
    /// Names the principal's account: the principal's own policies must allow it too.
    Account,
    /// Names everyone, or a session's role: allowed if its permissions boundary and
    /// session policy (if any) allow it.
    Limited,
    /// Names the user or session itself: allowed.
    Named,
}

impl Policy {
    /// Reads a policy document.
    pub fn parse(text: &str, kind: Kind) -> Result<Self, Error> {
        let Json::Object(fields) = Json::parse(text)? else {
            return Err(Error::new("a policy is a JSON object"));
        };
        let (mut version, mut id, mut statements) = (None, None, None);
        for (name, value) in fields {
            match name.as_str() {
                "Version" => version = Some(value),
                "Id" => id = Some(value),
                "Statement" => statements = Some(value),
                other => return Err(unknown_element(other)),
            }
        }
        let version = match version {
            None => Version::V2008_10_17,
            Some(Json::String(v)) if v == "2012-10-17" => Version::V2012_10_17,
            Some(Json::String(v)) if v == "2008-10-17" => Version::V2008_10_17,
            Some(_) => {
                return Err(Error::new(
                    "Version must be \"2012-10-17\" (or the older \"2008-10-17\")",
                ));
            }
        };
        let id = match id {
            None => None,
            Some(Json::String(id)) => Some(id),
            Some(other) => {
                return Err(Error::new(format!(
                    "Id must be a string, not {}",
                    other.kind()
                )));
            }
        };
        let statements = match statements {
            None => return Err(Error::new("a policy needs a Statement")),
            Some(Json::Array(list)) if list.is_empty() => {
                return Err(Error::new("Statement is an empty list"));
            }
            Some(Json::Array(list)) => list,
            Some(one @ Json::Object(_)) => vec![one],
            Some(other) => {
                return Err(Error::new(format!(
                    "Statement must be an object or a list of them, not {}",
                    other.kind()
                )));
            }
        };
        let statements = statements
            .into_iter()
            .enumerate()
            .map(|(i, json)| {
                Statement::parse(json, version, kind)
                    .map_err(|e| e.within(format!("Statement {}", i + 1)))
            })
            .collect::<Result<Box<[Statement]>, Error>>()?;
        let mut sids: Vec<&str> = statements.iter().filter_map(|s| s.sid.as_deref()).collect();
        sids.sort_unstable();
        if let Some([sid, _]) = sids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(Error::new(format!("two statements have the Sid `{sid}`")));
        }
        Ok(Self {
            version,
            id,
            kind,
            statements,
        })
    }

    /// The language version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The optional `Id`.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Where the policy goes.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// How many statements it has.
    #[must_use]
    pub fn statement_count(&self) -> usize {
        self.statements.len()
    }

    /// Checks what S3 checks of a bucket policy beyond the language: every action is an
    /// S3 action (a pattern must match at least one), and every `s3:` condition key is
    /// one S3 defines.
    pub fn check_s3(&self) -> Result<(), Error> {
        for (i, statement) in self.statements.iter().enumerate() {
            let within = |e: Error| e.within(format!("Statement {}", i + 1));
            for pattern in &statement.actions.patterns {
                let known = ACTIONS
                    .iter()
                    .any(|(action, _)| pattern::matches(pattern, action, true));
                if !known {
                    let text: String = pattern
                        .iter()
                        .map(|atom| match atom {
                            Atom::Char(c) => *c,
                            Atom::Star => '*',
                            Atom::One => '?',
                        })
                        .collect();
                    return Err(within(Error::new(format!("`{text}` isn't an S3 action"))));
                }
            }
        }
        if let Some(name) = self.unknown_condition_keys().find(|name| {
            name.get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("s3:"))
        }) {
            return Err(Error::new(format!("`{name}` isn't an S3 condition key")));
        }
        Ok(())
    }

    /// Checks a bucket policy for `bucket`: [`Self::check_s3`], and every `Resource` can
    /// be the bucket or its objects (a policy on one bucket can't grant another).
    pub fn check_bucket(&self, bucket: &str) -> Result<(), Error> {
        self.check_s3()?;
        let arn = crate::bucket_arn(bucket);
        let objects = format!("{arn}/");
        for (i, statement) in self.statements.iter().enumerate() {
            if statement.resources.negated {
                continue;
            }
            for template in &statement.resources.templates {
                let (prefix, whole) = template.literal_prefix();
                let within = prefix.starts_with(&objects)
                    || if whole {
                        prefix == arn
                    } else {
                        objects.starts_with(prefix)
                    };
                if !within {
                    return Err(Error::new(format!(
                        "Policy has invalid resource: `{prefix}…` isn't bucket {bucket} or its objects"
                    ))
                    .within(format!("Statement {}", i + 1)));
                }
            }
        }
        Ok(())
    }

    /// Whether S3 counts the policy as public: some `Allow` reaches everyone
    /// (`"Principal": "*"`) without a condition that pins it to fixed callers or places
    /// (`aws:SourceIp` no broader than a `/8`, `aws:SourceVpc`, `aws:PrincipalArn`…).
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.statements.iter().any(|s| {
            s.effect == Effect::Allow
                && s.principal
                    .as_ref()
                    .is_some_and(|p| p.entries.contains(&PrincipalEntry::Anyone))
                && !s.conditions.iter().any(Condition::pins_caller)
        })
    }

    /// The condition keys TeiFS doesn't know, which no request ever has: usually a typo.
    pub fn unknown_condition_keys(&self) -> impl Iterator<Item = &str> {
        self.statements
            .iter()
            .flat_map(|statement| statement.conditions.iter())
            .filter_map(|condition| match condition.key() {
                Key::Unknown(name) => Some(&**name),
                _ => None,
            })
    }

    /// Whether a statement denies the request.
    pub(crate) fn denies(&self, request: &Request<'_>) -> bool {
        self.statements.iter().any(|s| {
            s.effect == Effect::Deny
                && s.applies(request)
                && s.principal
                    .as_ref()
                    .is_none_or(|p| p.covers(request.context.principal()))
        })
    }

    /// Whether a statement allows the request (principals aside: for identity policies).
    pub(crate) fn allows(&self, request: &Request<'_>) -> bool {
        self.statements
            .iter()
            .any(|s| s.effect == Effect::Allow && s.principal.is_none() && s.applies(request))
    }

    /// How directly an `Allow` in this resource policy names the principal, at best.
    pub(crate) fn grant(&self, request: &Request<'_>) -> Option<Grant> {
        let principal = request.context.principal();
        self.statements
            .iter()
            .filter(|s| s.effect == Effect::Allow)
            .filter_map(|s| {
                let grant = s.principal.as_ref()?.grant(principal)?;
                s.applies(request).then_some(grant)
            })
            .max()
    }
}

impl Statement {
    fn parse(json: Json, version: Version, kind: Kind) -> Result<Self, Error> {
        let Json::Object(fields) = json else {
            return Err(Error::new(format!(
                "a statement is an object, not {}",
                json.kind()
            )));
        };
        let mut sid = None;
        let mut effect = None;
        let mut principal = None;
        let mut actions = None;
        let mut resources = None;
        let mut conditions = None;
        for (name, value) in fields {
            match name.as_str() {
                "Sid" => match value {
                    Json::String(s) => sid = Some(s),
                    other => {
                        return Err(Error::new(format!(
                            "Sid must be a string, not {}",
                            other.kind()
                        )));
                    }
                },
                "Effect" => match value {
                    Json::String(s) if s == "Allow" => effect = Some(Effect::Allow),
                    Json::String(s) if s == "Deny" => effect = Some(Effect::Deny),
                    _ => return Err(Error::new("Effect must be \"Allow\" or \"Deny\"")),
                },
                "Principal" | "NotPrincipal" => {
                    not_both(principal.as_ref(), "Principal", "NotPrincipal")?;
                    principal = Some(
                        Principals::parse(&value, name == "NotPrincipal")
                            .map_err(|e| e.within(&name))?,
                    );
                }
                "Action" | "NotAction" => {
                    not_both(actions.as_ref(), "Action", "NotAction")?;
                    actions = Some(
                        Actions::parse(&value, name == "NotAction").map_err(|e| e.within(&name))?,
                    );
                }
                "Resource" | "NotResource" => {
                    not_both(resources.as_ref(), "Resource", "NotResource")?;
                    resources = Some(
                        Resources::parse(&value, name == "NotResource", version)
                            .map_err(|e| e.within(&name))?,
                    );
                }
                "Condition" => {
                    conditions =
                        Some(condition::parse(&value, version).map_err(|e| e.within("Condition"))?);
                }
                other => return Err(unknown_element(other)),
            }
        }
        let effect = effect.ok_or_else(|| Error::new("a statement needs an Effect"))?;
        match (kind, &principal) {
            (Kind::Identity, Some(_)) => {
                return Err(Error::new(
                    "an identity policy applies to whoever holds it, so it names no Principal",
                ));
            }
            (Kind::Resource, None) => {
                return Err(Error::new(
                    "a resource policy's statement names a Principal",
                ));
            }
            (_, Some(p)) if p.negated && effect == Effect::Allow => {
                return Err(Error::new(
                    "NotPrincipal goes only with \"Deny\" (with \"Allow\" it would grant everyone else)",
                ));
            }
            _ => {}
        }
        Ok(Self {
            sid,
            effect,
            principal,
            actions: actions
                .ok_or_else(|| Error::new("a statement needs an Action or NotAction"))?,
            resources: resources
                .ok_or_else(|| Error::new("a statement needs a Resource or NotResource"))?,
            conditions: conditions.unwrap_or_default().into(),
        })
    }

    /// Action, resource and conditions (not the principal).
    fn applies(&self, request: &Request<'_>) -> bool {
        self.actions.matches(request.action)
            && self.resources.matches(request.resource, request.context)
            && self.conditions.iter().all(|c| c.holds(request.context))
    }
}

impl Principals {
    fn parse(json: &Json, negated: bool) -> Result<Self, Error> {
        let entries: Vec<PrincipalEntry> = match json {
            Json::String(s) if s == "*" => vec![PrincipalEntry::Anyone],
            Json::Object(kinds) if !kinds.is_empty() => {
                let mut entries = Vec::new();
                for (kind, values) in kinds {
                    for value in strings(values).map_err(|e| e.within(kind))? {
                        entries.push(PrincipalEntry::parse(kind, value)?);
                    }
                }
                entries
            }
            _ => {
                return Err(Error::new(
                    "a principal is \"*\" or an object like {\"AWS\": \"arn:aws:iam::123456789012:user/alice\"}",
                ));
            }
        };
        if negated && entries.contains(&PrincipalEntry::Anyone) {
            return Err(Error::new("NotPrincipal can't be everyone (\"*\")"));
        }
        Ok(Self {
            negated,
            entries: entries.into(),
        })
    }

    /// Whether a `Deny` with these principals reaches `principal`.
    fn covers(&self, principal: &Principal) -> bool {
        if self.negated {
            !self.entries.iter().any(|entry| entry.exempts(principal))
        } else {
            self.entries
                .iter()
                .any(|entry| entry.grant(principal).is_some())
        }
    }

    /// How directly an `Allow` with these principals names `principal`, at best.
    fn grant(&self, principal: &Principal) -> Option<Grant> {
        debug_assert!(!self.negated, "refused when parsed");
        self.entries
            .iter()
            .filter_map(|entry| entry.grant(principal))
            .max()
    }
}

impl PrincipalEntry {
    fn parse(kind: &str, value: &str) -> Result<Self, Error> {
        let bad = || {
            Error::new(format!(
                "`{value}` isn't a principal TeiFS can name under {kind}"
            ))
        };
        match kind {
            "AWS" => {
                if value == "*" {
                    return Ok(Self::Anyone);
                }
                if value.contains(['*', '?']) {
                    return Err(Error::new(format!(
                        "`{value}`: principals can't have wildcards (use a condition on aws:PrincipalArn)"
                    )));
                }
                if is_account(value) {
                    return Ok(Self::Account(value.into()));
                }
                let rest = value.strip_prefix("arn:aws:").ok_or_else(bad)?;
                let (service, rest) = rest.split_once("::").ok_or_else(bad)?;
                let (account, resource) = rest.split_once(':').ok_or_else(bad)?;
                if !is_account(account) {
                    return Err(bad());
                }
                let named = |prefix: &str, parts: usize| {
                    resource.strip_prefix(prefix).is_some_and(|name| {
                        name.split('/').count() >= parts && !name.split('/').any(str::is_empty)
                    })
                };
                match service {
                    "iam" if resource == "root" => Ok(Self::Account(account.into())),
                    "iam" if named("user/", 1) || named("role/", 1) => Ok(Self::Arn(value.into())),
                    "sts" if named("assumed-role/", 2) || named("federated-user/", 1) => {
                        Ok(Self::Arn(value.into()))
                    }
                    _ => Err(bad()),
                }
            }
            "CanonicalUser" if !value.is_empty() && value != "*" => {
                Ok(Self::Canonical(value.into()))
            }
            "Service" | "Federated" if !value.is_empty() => Ok(Self::Never),
            "CanonicalUser" | "Service" | "Federated" => Err(bad()),
            other => Err(Error::new(format!(
                "`{other}` isn't a kind of principal (AWS, CanonicalUser, Service, Federated)"
            ))),
        }
    }

    fn grant(&self, principal: &Principal) -> Option<Grant> {
        match self {
            Self::Anyone => Some(Grant::Limited),
            Self::Account(account) => {
                (principal.account() == Some(account)).then_some(Grant::Account)
            }
            Self::Arn(arn) => {
                if principal.arn() == Some(arn) {
                    Some(Grant::Named)
                } else if principal.role_arn() == Some(arn) {
                    Some(Grant::Limited)
                } else {
                    None
                }
            }
            Self::Canonical(id) => (principal.canonical_id() == Some(id)).then_some(Grant::Named),
            Self::Never => None,
        }
    }

    /// Whether `NotPrincipal` naming this spares `principal` from the `Deny`. An account
    /// spares only its root user, not everyone in it: when in doubt, deny.
    fn exempts(&self, principal: &Principal) -> bool {
        match self {
            Self::Anyone => true,
            Self::Account(account) => {
                principal.kind() == crate::PrincipalKind::Account
                    && principal.account() == Some(account)
            }
            Self::Arn(arn) => principal.arn() == Some(arn) || principal.role_arn() == Some(arn),
            Self::Canonical(id) => principal.canonical_id() == Some(id),
            Self::Never => false,
        }
    }
}

impl Actions {
    fn parse(json: &Json, negated: bool) -> Result<Self, Error> {
        let patterns = strings(json)?
            .into_iter()
            .map(|action| {
                let valid = action == "*"
                    || action.split_once(':').is_some_and(|(service, name)| {
                        !service.is_empty()
                            && service
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            && !name.is_empty()
                            && name.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'*' | b'?' | b'-' | b'_')
                            })
                    });
                if valid {
                    Ok(pattern::atoms(action).collect())
                } else {
                    Err(Error::new(format!(
                        "`{action}` isn't an action like s3:GetObject"
                    )))
                }
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self { negated, patterns })
    }

    /// Actions compare without case: `s3:getobject` is `s3:GetObject`.
    fn matches(&self, action: &str) -> bool {
        self.patterns
            .iter()
            .any(|p| pattern::matches(p, action, true))
            != self.negated
    }
}

impl Resources {
    fn parse(json: &Json, negated: bool, version: Version) -> Result<Self, Error> {
        let templates = strings(json)?
            .into_iter()
            .map(|resource| {
                let shaped = resource == "*"
                    || (resource.starts_with("arn:")
                        && (resource.matches(':').count() >= 5 || resource.ends_with('*')));
                if !shaped {
                    return Err(Error::new(format!(
                        "`{resource}` isn't an ARN (arn:aws:s3:::bucket/key) or \"*\""
                    )));
                }
                let template = match version {
                    Version::V2012_10_17 => Template::parse(resource)?,
                    Version::V2008_10_17 => Template::plain(resource),
                };
                if template.colons_before_variable().is_some_and(|colons| colons < 5) {
                    return Err(Error::new(format!(
                        "`{resource}`: variables go only in the resource part of an ARN, after the fifth `:`"
                    )));
                }
                Ok(template)
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self { negated, templates })
    }

    /// A resource with a variable the request has no value for matches nothing.
    fn matches(&self, resource: &str, context: &crate::Context) -> bool {
        self.templates.iter().any(|t| {
            t.atoms(context)
                .is_some_and(|atoms| crate::arn::matches(&atoms, resource))
        }) != self.negated
    }
}

/// A string, or a non-empty list of strings.
fn strings(json: &Json) -> Result<Vec<&str>, Error> {
    match json {
        Json::String(s) if !s.is_empty() => Ok(vec![s.as_str()]),
        Json::Array(items) if !items.is_empty() => items
            .iter()
            .map(|item| match item {
                Json::String(s) if !s.is_empty() => Ok(s.as_str()),
                other => Err(Error::new(format!(
                    "expected a non-empty string, not {}",
                    other.kind()
                ))),
            })
            .collect(),
        Json::String(_) | Json::Array(_) => Err(Error::new("is empty")),
        other => Err(Error::new(format!(
            "must be a string or a list of strings, not {}",
            other.kind()
        ))),
    }
}

/// An element and its negation are exclusive: `Action` or `NotAction`.
fn not_both<T>(seen: Option<&T>, positive: &str, negative: &str) -> Result<(), Error> {
    if seen.is_some() {
        Err(Error::new(format!(
            "a statement has {positive} or {negative}, not both"
        )))
    } else {
        Ok(())
    }
}

fn is_account(text: &str) -> bool {
    text.len() == 12 && text.bytes().all(|b| b.is_ascii_digit())
}

fn unknown_element(name: &str) -> Error {
    Error::new(format!(
        "`{name}` isn't a policy element (element names are case-sensitive)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(text: &str, kind: Kind) -> String {
        Policy::parse(text, kind).unwrap_err().to_string()
    }

    fn statement(body: &str) -> String {
        format!(r#"{{"Version": "2012-10-17", "Statement": {{{body}}}}}"#)
    }

    #[test]
    fn well_formed_policies() {
        let policy = Policy::parse(
            r#"{"Version": "2012-10-17", "Id": "p1", "Statement": [
                {"Sid": "Read", "Effect": "Allow", "Action": ["s3:GetObject", "s3:List*"],
                 "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]},
                {"Effect": "Deny", "NotAction": "s3:*", "NotResource": "*",
                 "Condition": {"Bool": {"aws:SecureTransport": false}}}
            ]}"#,
            Kind::Identity,
        )
        .unwrap();
        assert_eq!(policy.version(), Version::V2012_10_17);
        assert_eq!(policy.id(), Some("p1"));
        assert_eq!(policy.statement_count(), 2);
        assert_eq!(policy.kind(), Kind::Identity);

        let old = Policy::parse(
            r#"{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}"#,
            Kind::Identity,
        )
        .unwrap();
        assert_eq!(
            old.version(),
            Version::V2008_10_17,
            "no Version is 2008-10-17"
        );

        let bucket = Policy::parse(
            r#"{"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
                {"Effect": "Allow", "Principal": {"AWS": ["123456789012", "arn:aws:iam::123456789012:root",
                   "arn:aws:iam::123456789012:user/eng/alice", "arn:aws:iam::123456789012:role/r",
                   "arn:aws:sts::123456789012:assumed-role/r/s"]}, "Action": "s3:*", "Resource": "*"},
                {"Effect": "Deny", "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:user/bob"},
                 "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::b/*"},
                {"Effect": "Allow", "Principal": {"Service": "logging.s3.amazonaws.com", "CanonicalUser": "abc"},
                 "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/logs/*"}
            ]}"#,
            Kind::Resource,
        )
        .unwrap();
        assert_eq!(bucket.statement_count(), 4);
        bucket.check_s3().unwrap();
    }

    #[test]
    fn malformed_documents_are_refused() {
        let identity = Kind::Identity;
        assert!(refused("", identity).contains("not valid JSON"));
        assert!(refused("[]", identity).contains("JSON object"));
        assert!(refused(r#"{"Version": "2012-10-17"}"#, identity).contains("needs a Statement"));
        assert!(
            refused(r#"{"Version": "2012-10-17", "Statement": []}"#, identity)
                .contains("empty list")
        );
        assert!(
            refused(r#"{"Version": "2012-10-17", "Statement": "x"}"#, identity)
                .contains("not a string")
        );
        assert!(
            refused(r#"{"Version": "2012-10-18", "Statement": {}}"#, identity)
                .contains("Version must be")
        );
        assert!(
            refused(r#"{"Version": 2012, "Statement": {}}"#, identity).contains("Version must be")
        );
        assert!(
            refused(r#"{"version": "2012-10-17", "Statement": {}}"#, identity)
                .contains("case-sensitive")
        );
        assert!(refused(r#"{"Id": 1, "Statement": {}}"#, identity).contains("Id must be a string"));
        assert!(
            refused(r#"{"Statement": {"Effect": "Allow", "Effect": "Deny", "Action": "*", "Resource": "*"}}"#, identity)
                .contains("appears twice")
        );
        let twice = r#"{"Statement": [
            {"Sid": "A", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "A", "Effect": "Deny", "Action": "*", "Resource": "*"}]}"#;
        assert!(refused(twice, identity).contains("Sid `A`"));
    }

    #[test]
    fn malformed_statements_are_refused() {
        let identity = Kind::Identity;
        for (body, says) in [
            (r#""Action": "*", "Resource": "*""#, "needs an Effect"),
            (
                r#""Effect": "allow", "Action": "*", "Resource": "*""#,
                "Effect must be",
            ),
            (r#""Effect": "Allow", "Resource": "*""#, "needs an Action"),
            (r#""Effect": "Allow", "Action": "*""#, "needs a Resource"),
            (
                r#""Effect": "Allow", "Action": "*", "NotAction": "s3:x", "Resource": "*""#,
                "not both",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "*", "NotResource": "*""#,
                "not both",
            ),
            (
                r#""Effect": "Allow", "Action": [], "Resource": "*""#,
                "Action: is empty",
            ),
            (
                r#""Effect": "Allow", "Action": "", "Resource": "*""#,
                "is empty",
            ),
            (
                r#""Effect": "Allow", "Action": ["s3:GetObject", 7], "Resource": "*""#,
                "not a number",
            ),
            (
                r#""Effect": "Allow", "Action": "GetObject", "Resource": "*""#,
                "isn't an action",
            ),
            (
                r#""Effect": "Allow", "Action": "s3:Get Object", "Resource": "*""#,
                "isn't an action",
            ),
            (
                r#""Effect": "Allow", "Action": "s3:", "Resource": "*""#,
                "isn't an action",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "bucket/*""#,
                "isn't an ARN",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3""#,
                "isn't an ARN",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/${aws:username""#,
                "without its",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:${aws:username}::b""#,
                "resource part",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "*", "Principal": "*""#,
                "names no Principal",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Nope": {"a": "b"}}"#,
                "operator",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "*", "Extra": 1"#,
                "`Extra` isn't a policy element",
            ),
            (
                r#""Effect": "Allow", "Action": "*", "Resource": "*", "Sid": 1"#,
                "Sid must be a string",
            ),
        ] {
            let message = refused(&statement(body), identity);
            assert!(message.contains(says), "{body}: {message}");
            assert!(message.starts_with("Statement 1"), "{message}");
        }
    }

    #[test]
    fn principals_are_checked() {
        let resource = Kind::Resource;
        let with = |principal: &str| {
            statement(&format!(
                r#""Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Principal": {principal}"#
            ))
        };
        for (principal, says) in [
            ("\"alice\"", "a principal is"),
            ("{}", "a principal is"),
            (
                r#"{"AWS": "arn:aws:iam::123456789012:user/*"}"#,
                "wildcards",
            ),
            (r#"{"AWS": "arn:aws:iam::*:root"}"#, "wildcards"),
            (r#"{"AWS": "12345"}"#, "isn't a principal"),
            (
                r#"{"AWS": "arn:aws:iam::123456789012:group/g"}"#,
                "isn't a principal",
            ),
            (
                r#"{"AWS": "arn:aws:iam::123456789012:user/"}"#,
                "isn't a principal",
            ),
            (
                r#"{"AWS": "arn:aws:sts::123456789012:assumed-role/r"}"#,
                "isn't a principal",
            ),
            (r#"{"AWS": "arn:aws:s3:::bucket"}"#, "isn't a principal"),
            (
                r#"{"AWS": "arn:aws:iam:us-east-1:123456789012:user/a"}"#,
                "isn't a principal",
            ),
            (r#"{"AWS": []}"#, "is empty"),
            (r#"{"Everyone": "*"}"#, "isn't a kind of principal"),
            (r#"{"CanonicalUser": "*"}"#, "isn't a principal"),
        ] {
            let message = refused(&with(principal), resource);
            assert!(message.contains(says), "{principal}: {message}");
        }
        let no_principal =
            statement(r#""Effect": "Allow", "Action": "s3:GetObject", "Resource": "*""#);
        assert!(refused(&no_principal, resource).contains("names a Principal"));
        let not_allow = statement(
            r#""Effect": "Allow", "NotPrincipal": {"AWS": "123456789012"}, "Action": "s3:GetObject", "Resource": "*""#,
        );
        assert!(refused(&not_allow, resource).contains("only with \"Deny\""));
        let not_everyone = statement(
            r#""Effect": "Deny", "NotPrincipal": "*", "Action": "s3:GetObject", "Resource": "*""#,
        );
        assert!(refused(&not_everyone, resource).contains("can't be everyone"));
        let both = statement(
            r#""Effect": "Deny", "Principal": "*", "NotPrincipal": {"AWS": "123456789012"}, "Action": "*", "Resource": "*""#,
        );
        assert!(refused(&both, resource).contains("not both"));
    }

    #[test]
    fn s3_checks_for_bucket_policies() {
        let check = |action: &str, condition: &str| {
            Policy::parse(
                &statement(&format!(
                    r#""Effect": "Allow", "Principal": "*", "Action": "{action}", "Resource": "*", "Condition": {condition}"#
                )),
                Kind::Resource,
            )
            .unwrap()
            .check_s3()
        };
        let none = "{}";
        assert!(check("s3:GetObject", none).is_ok());
        assert!(
            check("S3:getobject", none).is_ok(),
            "actions compare without case"
        );
        assert!(check("s3:Get*", none).is_ok());
        assert!(check("*", none).is_ok());
        assert!(check("s3:*", none).is_ok());
        assert!(
            check("s3:GetObjects", none)
                .unwrap_err()
                .to_string()
                .contains("isn't an S3 action")
        );
        assert!(check("s3:Nothing*", none).is_err());
        assert!(check("iam:CreateUser", none).is_err());
        assert!(check("s3:GetObject", r#"{"StringEquals": {"s3:prefix": "a"}}"#).is_ok());
        assert!(
            check("s3:GetObject", r#"{"StringEquals": {"aws:madeUp": "a"}}"#).is_ok(),
            "only s3: keys are checked"
        );
        let unknown = check("s3:GetObject", r#"{"StringEquals": {"s3:madeUp": "a"}}"#).unwrap_err();
        assert!(
            unknown
                .to_string()
                .contains("`s3:madeUp` isn't an S3 condition key"),
            "{unknown}"
        );
        assert!(
            check(
                "s3:GetObject",
                r#"{"StringEquals": {"s3:ExistingObjectTag/team": "a"}}"#
            )
            .is_ok()
        );
    }

    #[test]
    fn public_is_everyone_without_a_fixed_caller() {
        let public = |principal: &str, condition: &str| {
            let condition = if condition.is_empty() {
                String::new()
            } else {
                format!(r#", "Condition": {condition}"#)
            };
            Policy::parse(
                &statement(&format!(
                    r#""Effect": "Allow", "Principal": {principal}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"{condition}"#
                )),
                Kind::Resource,
            )
            .unwrap()
            .is_public()
        };
        let everyone = r#""*""#;
        // AWS's own examples.
        assert!(public(everyone, ""));
        assert!(public(
            everyone,
            r#"{"StringLike": {"aws:SourceVpc": "vpc-*"}}"#
        ));
        assert!(!public(
            everyone,
            r#"{"StringEquals": {"aws:SourceVpc": "vpc-91237329"}}"#
        ));
        assert!(public(r#"{"AWS": "*"}"#, ""));
        for named in [
            r#"{"AWS": "123456789012"}"#,
            r#"{"AWS": "arn:aws:iam::123456789012:user/alice"}"#,
            r#"{"Service": "cloudtrail.amazonaws.com"}"#,
            r#"{"CanonicalUser": "abc"}"#,
        ] {
            assert!(!public(named, ""), "{named}");
        }
        assert!(public(r#"{"AWS": ["123456789012", "*"]}"#, ""));
        for pinned in [
            r#"{"IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "10.0.0.0/8", "2001:db8::/32"]}}"#,
            r#"{"StringEquals": {"aws:PrincipalOrgID": "o-123"}}"#,
            r#"{"StringEquals": {"aws:PrincipalAccount": "123456789012"}}"#,
            r#"{"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/a"}}"#,
            r#"{"ArnLike": {"aws:SourceArn": "arn:aws:s3:::logs"}}"#,
            r#"{"StringEquals": {"aws:SourceAccount": "123456789012"}}"#,
            r#"{"StringEquals": {"aws:SourceOwner": "123456789012"}}"#,
            r#"{"StringEquals": {"aws:SourceVpce": "vpce-1"}}"#,
            r#"{"StringEquals": {"aws:userid": "AIDAEXAMPLE"}}"#,
            r#"{"StringEquals": {"s3:DataAccessPointAccount": "123456789012"}}"#,
            r#"{"StringLike": {"s3:DataAccessPointArn": "arn:aws:s3:us-west-2:123456789012:accesspoint/*"}}"#,
            r#"{"ForAnyValue:StringEquals": {"aws:SourceVpc": ["vpc-1", "vpc-2"]}}"#,
            // One pinning condition is enough; the others only narrow it further.
            r#"{"Bool": {"aws:SecureTransport": "true"}, "StringEquals": {"aws:SourceVpc": "vpc-1"}}"#,
        ] {
            assert!(!public(everyone, pinned), "{pinned}");
        }
        for open in [
            r#"{"IpAddress": {"aws:SourceIp": "0.0.0.0/1"}}"#,
            r#"{"IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "0.0.0.0/7"]}}"#,
            r#"{"IpAddress": {"aws:SourceIp": "2001::/16"}}"#,
            r#"{"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}"#,
            r#"{"StringNotEquals": {"aws:SourceVpc": "vpc-1"}}"#,
            r#"{"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}"#,
            r#"{"ForAllValues:StringEquals": {"aws:SourceVpc": "vpc-1"}}"#,
            r#"{"StringEquals": {"aws:SourceVpc": "${aws:username}"}}"#,
            r#"{"StringLike": {"aws:userid": "AROAEXAMPLE:*"}}"#,
            r#"{"StringLike": {"s3:DataAccessPointArn": "arn:aws:s3:us-west-2:*:accesspoint/x"}}"#,
            r#"{"StringEquals": {"aws:PrincipalOrgPaths": "o-1/r-1/"}}"#,
            r#"{"Bool": {"aws:SecureTransport": "true"}}"#,
            r#"{"StringEquals": {"s3:prefix": "home/"}}"#,
            r#"{"Null": {"aws:SourceVpc": "false"}}"#,
        ] {
            assert!(public(everyone, open), "{open}");
        }
        let deny = Policy::parse(
            &statement(
                r#""Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*""#,
            ),
            Kind::Resource,
        )
        .unwrap();
        assert!(!deny.is_public(), "a Deny makes nothing public");
    }

    #[test]
    fn bucket_policies_are_about_their_bucket() {
        let check = |resource: &str| {
            Policy::parse(
                &statement(&format!(
                    r#""Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": {resource}"#
                )),
                Kind::Resource,
            )
            .unwrap()
            .check_bucket("photos")
        };
        for fine in [
            r#""arn:aws:s3:::photos""#,
            r#""arn:aws:s3:::photos/*""#,
            r#""arn:aws:s3:::photos/a/b.jpg""#,
            r#""arn:aws:s3:::photos/${aws:username}/*""#,
            r#""arn:aws:s3:::pho*""#,
            r#""arn:aws:s3:::photo?/*""#,
            r#""*""#,
            r#"["arn:aws:s3:::photos", "arn:aws:s3:::photos/*"]"#,
        ] {
            assert!(check(fine).is_ok(), "{fine}");
        }
        for wrong in [
            r#""arn:aws:s3:::photosx""#,
            r#""arn:aws:s3:::photosx/*""#,
            r#""arn:aws:s3:::other/*""#,
            r#""arn:aws:s3:::Photos/*""#,
            r#"["arn:aws:s3:::photos/*", "arn:aws:s3:::other"]"#,
            r#""arn:aws:iam::123456789012:user/a""#,
        ] {
            let err = check(wrong).unwrap_err().to_string();
            assert!(
                err.contains("Policy has invalid resource"),
                "{wrong}: {err}"
            );
        }
        let everything_else = Policy::parse(
            &statement(
                r#""Effect": "Deny", "Principal": "*", "Action": "s3:*", "NotResource": "arn:aws:s3:::other/*""#,
            ),
            Kind::Resource,
        )
        .unwrap();
        assert!(everything_else.check_bucket("photos").is_ok());
        let not_s3 = Policy::parse(
            &statement(
                r#""Effect": "Allow", "Principal": "*", "Action": "iam:GetUser", "Resource": "arn:aws:s3:::photos""#,
            ),
            Kind::Resource,
        )
        .unwrap();
        assert!(not_s3.check_bucket("photos").is_err());
    }

    #[test]
    fn grants_rank() {
        assert!(Grant::Named > Grant::Limited && Grant::Limited > Grant::Account);
    }
}
