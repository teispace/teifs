//! Web identities: the OpenID Connect ID tokens `AssumeRoleWithWebIdentity` exchanges for
//! a role's session, checked as AWS checks them.
//!
//! A token is accepted when its issuer (`iss`) is the URL of one of the account's
//! OpenID Connect providers, that provider's current keys verify its signature, it's
//! for one of the provider's client ids (`azp` if it has one, else `aud`), it names
//! its subject (`sub`), and it hasn't expired (`exp`, which it must have) and has been
//! issued (`nbf` and `iat`, with a minute's leeway for clocks that differ).

pub(crate) mod jwt;
pub(crate) mod keys;
pub(crate) mod tls;

use teifs_policy::{Context, Json, Value};

pub(crate) use self::keys::KeyCache;
use crate::state::{OidcProvider, State};

/// How far in the future a token's `nbf` and `iat` may be, for clocks that differ.
const LEEWAY: i64 = 60;
/// The longest subject (`sub`) accepted, as AWS's `SubjectFromWebIdentityToken`.
const MAX_SUBJECT: usize = 255;

/// Claims that say what AWS should do with a token (`https://aws.amazon.com/tags`).
pub(crate) const ROLES_CLAIM: &str = "https://aws.amazon.com/roles";
pub(crate) const TAGS_CLAIM: &str = "https://aws.amazon.com/tags";
pub(crate) const SOURCE_IDENTITY_CLAIM: &str = "https://aws.amazon.com/source_identity";

/// The tag that lets a provider's tokens name the account's managed policies in a
/// claim, for MinIO's `AssumeRoleWithWebIdentity` without a role: its value names the
/// claim, and no value means MinIO's `policy`.
pub(crate) const POLICY_CLAIM_TAG: &str = "teifs:policy-claim";
const DEFAULT_POLICY_CLAIM: &str = "policy";

/// The tag that gives a provider MinIO's role policies: its value names the managed
/// policies (separated by spaces, since a tag can't hold commas) that every token of each of its clients gets, when
/// the request names that client's role ([`crate::openid_role_arn`]).
pub(crate) const ROLE_POLICY_TAG: &str = "teifs:role-policy";

/// Whether the issuer `a` is `b`: the same, or the same but for a trailing slash.
pub(crate) fn same_issuer(a: &str, b: &str) -> bool {
    a == b || a.strip_suffix('/').unwrap_or(a) == b.strip_suffix('/').unwrap_or(b)
}

/// Why a web identity token isn't accepted: AWS's error codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    /// `InvalidIdentityToken`.
    Invalid(String),
    /// `ExpiredTokenException`.
    Expired(String),
    /// `IDPCommunicationError`: the provider's keys couldn't be fetched.
    Unreachable(String),
}

impl From<jwt::Invalid> for Refused {
    fn from(err: jwt::Invalid) -> Self {
        Self::Invalid(err.0)
    }
}

/// A token its provider vouches for.
#[derive(Debug, Clone)]
pub(crate) struct WebIdentity {
    /// The provider's unique id.
    pub(crate) id: String,
    /// The claim that names managed policies, if the provider's tokens may
    /// ([`POLICY_CLAIM_TAG`]).
    pub(crate) policy_claim: Option<String>,
    /// The provider's ARN (`aws:FederatedProvider`, and `Provider` in the answer).
    pub(crate) provider: String,
    /// The provider's URL without its scheme: the prefix of its condition keys
    /// (`idp.example.com:sub`).
    pub(crate) prefix: String,
    /// `sub`.
    pub(crate) subject: String,
    /// `exp`, in seconds since the Unix epoch.
    pub(crate) expires: i64,
    /// The client id it's for: `azp`, or else the `aud` that's one of the provider's.
    pub(crate) audience: String,
    /// Every claim.
    pub(crate) claims: Json,
}

impl WebIdentity {
    /// The provider's condition keys a trust policy may test: `aud` (the client id),
    /// `oaud` (the token's own `aud`), and every other claim of text, a number, a
    /// boolean or a list of text (`sub`, `amr`, `email`, a GitHub token's
    /// `repository`), by the provider's prefix.
    pub(crate) fn with_keys(&self, mut context: Context) -> Context {
        let Json::Object(members) = &self.claims else {
            return context;
        };
        for (name, value) in members {
            let key = if name == "aud" { "oaud" } else { name };
            if let Some(value) = key_value(value) {
                context = context.with_claim(&format!("{}:{key}", self.prefix), value);
            }
        }
        context.with_claim(&format!("{}:aud", self.prefix), self.audience.as_str())
    }

    /// The authentication methods the provider says it used (`amr`).
    pub(crate) fn amr(&self) -> Vec<String> {
        strings(self.claims.get("amr")).unwrap_or_default()
    }
}

/// A claim's value as a condition key's: text, a number, a boolean, or a list of text.
fn key_value(json: &Json) -> Option<Value> {
    Some(match json {
        Json::String(text) => Value::String(text.clone()),
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => Value::String(n.to_string()),
        Json::Array(_) => Value::Strings(strings(Some(json))?),
        Json::Null | Json::Object(_) => return None,
    })
}

/// A string, or a list of strings, as a list.
pub(crate) fn strings(json: Option<&Json>) -> Option<Vec<String>> {
    match json? {
        Json::String(text) => Some(vec![text.clone()]),
        Json::Array(items) => items
            .iter()
            .map(|i| i.as_str().map(str::to_owned))
            .collect(),
        _ => None,
    }
}

/// A claim that's a whole number of seconds since the Unix epoch.
fn seconds(token: &jwt::Token, name: &str) -> Result<Option<i64>, Refused> {
    match token.claims.get(name) {
        None => Ok(None),
        Some(Json::Number(n)) => n.as_i64().map(Some).ok_or_else(|| {
            Refused::Invalid(format!(
                "The token's {name} isn't a whole number of seconds."
            ))
        }),
        Some(_) => Err(Refused::Invalid(format!(
            "The token's {name} isn't a number."
        ))),
    }
}

/// The claim a provider's tokens name managed policies in, if they may
/// ([`POLICY_CLAIM_TAG`]).
pub(crate) fn policy_claim(provider: &OidcProvider) -> Option<&str> {
    provider
        .tags
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(POLICY_CLAIM_TAG))
        .map(|(_, claim)| {
            if claim.is_empty() {
                DEFAULT_POLICY_CLAIM
            } else {
                claim.as_str()
            }
        })
}

/// The managed policies (by name) a provider's role policy names, if it has one
/// ([`ROLE_POLICY_TAG`]).
pub(crate) fn role_policies(provider: &OidcProvider) -> Option<Vec<String>> {
    provider
        .tags
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(ROLE_POLICY_TAG))
        .map(|(_, names)| {
            names
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect()
        })
}

impl State {
    /// The provider with a role policy whose client's MinIO role is `arn`: its unique
    /// id, the client, and the role's policies (by name).
    pub(crate) fn oidc_role(&self, arn: &str) -> Option<(String, String, Vec<String>)> {
        self.oidc_providers.values().find_map(|p| {
            let policies = role_policies(p)?;
            p.client_ids
                .iter()
                .find(|client| crate::openid_role_arn(client) == arn)
                .map(|client| (p.id.clone(), client.clone(), policies))
        })
    }

    /// The provider whose URL is the issuer `iss`.
    pub(crate) fn oidc_provider_by_issuer(&self, iss: &str) -> Option<&OidcProvider> {
        self.oidc_providers
            .values()
            .map(AsRef::as_ref)
            .find(|p| same_issuer(&p.url, iss))
    }
}

/// The issuer of the token `text`, and the key it's signed with, if it reads as a
/// token: what [`KeyCache::refresh`] needs before the token can be checked.
pub(crate) fn issuer(text: &str) -> Option<(String, Option<String>)> {
    let token = jwt::Token::decode(text).ok()?;
    Some((
        token.claim("iss")?.to_owned(),
        token.kid().map(str::to_owned),
    ))
}

/// Checks the token `text` at `now` (seconds since the Unix epoch) with the account's
/// providers and the keys in `cache`.
pub(crate) fn verify(
    state: &State,
    cache: &KeyCache,
    text: &str,
    now: i64,
) -> Result<WebIdentity, Refused> {
    let token = jwt::Token::decode(text)?;
    let Some(iss) = token.claim("iss") else {
        return Err(Refused::Invalid("The token names no issuer (iss).".into()));
    };
    let Some(provider) = state.oidc_provider_by_issuer(iss) else {
        return Err(Refused::Invalid(format!(
            "No OpenIDConnect provider found in your account for {iss}"
        )));
    };
    let keys = cache.keys(&provider.url).map_err(|why| {
        Refused::Unreachable(format!(
            "Couldn't get the signing keys of the OpenID Connect provider {}: {why}.",
            provider.url
        ))
    })?;
    token.verify(&keys)?;

    let Some(exp) = seconds(&token, "exp")? else {
        return Err(Refused::Invalid("The token has no expiry (exp).".into()));
    };
    if exp <= now {
        return Err(Refused::Expired(format!(
            "Token expired: current date/time {now} must be before the expiration date/time {exp}"
        )));
    }
    for name in ["nbf", "iat"] {
        if seconds(&token, name)?.is_some_and(|at| at > now + LEEWAY) {
            return Err(Refused::Invalid(format!(
                "The token's {name} is in the future."
            )));
        }
    }

    let audiences = match token.claims.get("aud") {
        None => Vec::new(),
        aud => strings(aud).ok_or_else(|| {
            Refused::Invalid("The token's aud isn't text or a list of text.".into())
        })?,
    };
    let azp = match token.claims.get("azp") {
        None => None,
        Some(Json::String(azp)) => Some(azp.as_str()),
        Some(_) => return Err(Refused::Invalid("The token's azp isn't text.".into())),
    };
    let audience = match azp {
        Some(azp) => provider.client_ids.iter().find(|c| *c == azp),
        None => provider
            .client_ids
            .iter()
            .find(|c| audiences.iter().any(|a| a == *c)),
    };
    let Some(audience) = audience else {
        return Err(Refused::Invalid("Incorrect token audience".into()));
    };

    let subject = match token.claims.get("sub") {
        Some(Json::String(sub)) if (1..=MAX_SUBJECT).contains(&sub.chars().count()) => sub,
        Some(Json::String(_)) => {
            return Err(Refused::Invalid(format!(
                "The token's subject (sub) must be 1 to {MAX_SUBJECT} characters."
            )));
        }
        _ => return Err(Refused::Invalid("The token names no subject (sub).".into())),
    };
    Ok(WebIdentity {
        id: provider.id.clone(),
        policy_claim: policy_claim(provider).map(str::to_owned),
        provider: state.oidc_provider_arn(provider),
        prefix: provider.name().to_owned(),
        subject: subject.clone(),
        expires: exp,
        audience: audience.clone(),
        claims: token.claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuers_compare_exactly_but_for_a_trailing_slash() {
        assert!(same_issuer("https://a.example", "https://a.example"));
        assert!(same_issuer("https://a.example/", "https://a.example"));
        assert!(same_issuer("https://a.example", "https://a.example/"));
        assert!(!same_issuer("https://a.example//", "https://a.example"));
        assert!(!same_issuer("https://A.example", "https://a.example"));
        assert!(!same_issuer("http://a.example", "https://a.example"));
        assert!(!same_issuer("https://a.example/x", "https://a.example"));
    }

    #[test]
    fn claims_become_the_providers_condition_keys() {
        let claims = Json::parse(
            r#"{"iss":"https://idp.example.com","sub":"repo:o/r:ref:refs/heads/main",
                "aud":["app","other"],"azp":"app","amr":["pwd","mfa"],"email_verified":true,
                "n":7,"nested":{"a":1},"none":null,"mixed":["a",1]}"#,
        )
        .unwrap();
        let web = WebIdentity {
            id: "OIDC".into(),
            policy_claim: None,
            provider: "arn:aws:iam::123456789012:oidc-provider/idp.example.com".into(),
            prefix: "idp.example.com".into(),
            subject: "repo:o/r:ref:refs/heads/main".into(),
            expires: 0,
            audience: "app".into(),
            claims,
        };
        assert_eq!(web.amr(), ["pwd", "mfa"]);
        let context = web.with_keys(Context::new(
            teifs_policy::Principal::web_identity(&web.provider, &web.subject),
            teifs_policy::Date::now(),
        ));
        let policy = |condition: &str| {
            teifs_policy::Policy::parse(
                &format!(
                    r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",
                        "Principal":{{"Federated":"{}"}},"Action":"sts:AssumeRoleWithWebIdentity",
                        "Condition":{condition}}}]}}"#,
                    web.provider
                ),
                teifs_policy::Kind::Trust,
            )
            .unwrap()
        };
        let allows = |condition: &str| {
            teifs_policy::evaluate(
                &teifs_policy::Policies {
                    identity: &[],
                    resource: Some(&policy(condition)),
                    boundary: None,
                    session: None,
                },
                &teifs_policy::Request {
                    action: "sts:AssumeRoleWithWebIdentity",
                    resource: "arn:aws:iam::123456789012:role/r",
                    context: &context,
                },
            )
            .is_allowed()
        };
        for condition in [
            r#"{"StringEquals":{"idp.example.com:aud":"app"}}"#,
            r#"{"StringLike":{"idp.example.com:sub":"repo:o/r:*"}}"#,
            r#"{"ForAnyValue:StringEquals":{"idp.example.com:oaud":"other"}}"#,
            r#"{"ForAnyValue:StringEquals":{"idp.example.com:amr":"mfa"}}"#,
            r#"{"Bool":{"idp.example.com:email_verified":"true"}}"#,
            r#"{"StringEquals":{"idp.example.com:n":"7"}}"#,
            r#"{"Null":{"idp.example.com:nested":"true","idp.example.com:mixed":"true"}}"#,
            r#"{"StringEquals":{"aws:FederatedProvider":"arn:aws:iam::123456789012:oidc-provider/idp.example.com"}}"#,
        ] {
            assert!(allows(condition), "{condition}");
        }
        for condition in [
            r#"{"StringEquals":{"idp.example.com:aud":"other"}}"#,
            r#"{"StringEquals":{"other.example.com:sub":"repo:o/r:ref:refs/heads/main"}}"#,
        ] {
            assert!(!allows(condition), "{condition}");
        }
    }
}
