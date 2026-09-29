//! Temporary credentials, as STS issues them: an access key id (`TSIA…`), a secret and a
//! session token, valid until they expire.
//!
//! Nothing about a session is stored. Its secret is derived from its access key id under
//! IAM's key, so the signature can be checked from the id alone; its token is its claims
//! (who it acts as, when it expires, its session policies and tags) sealed under IAM's
//! key and bound to the access key id, so a token works only with its own key and can't
//! be forged or changed. Every request turns the claims into an identity against IAM as
//! it is now: a deleted role or user takes its sessions' permissions with it.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Iam, Identity, ids};

/// The prefix of temporary access key ids (AWS's are `ASIA…`).
pub(crate) const PREFIX: &str = "TSIA";

/// The claims format version.
const VERSION: u8 = 1;

/// The most a token's claims may take, sealed: session policies and tags past it are
/// refused (`PackedPolicyTooLarge`), so a token always fits in a request's headers.
pub(crate) const PACKED_LIMIT: usize = 6144;

/// What a session token says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claims {
    pub(crate) v: u8,
    pub(crate) who: Who,
    /// Issued and expires, in seconds since the Unix epoch.
    pub(crate) iat: i64,
    pub(crate) exp: i64,
    /// Session policies' documents, as they were when the session began (AWS packs
    /// them into the token too).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) policies: Vec<String>,
    /// Session tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tags: Vec<(String, String)>,
    /// The keys of the tags that pass on to sessions this one starts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) transitive: Vec<String>,
    /// `SourceIdentity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<String>,
    /// The web identity that started it (`AssumeRoleWithWebIdentity`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) web: Option<WebClaims>,
}

/// What a role session keeps of the web identity token that started it: the provider's
/// condition keys its requests have (`idp.example.com:sub`), as on AWS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebClaims {
    /// The provider's ARN (`aws:FederatedProvider`).
    pub(crate) provider: String,
    /// `aud`: the client id the token was for.
    pub(crate) aud: String,
    /// `sub`.
    pub(crate) sub: String,
    /// `amr`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) amr: Vec<String>,
}

impl WebClaims {
    /// The provider's URL without its scheme: its condition keys' prefix.
    pub(crate) fn prefix(&self) -> &str {
        self.provider
            .split_once(":oidc-provider/")
            .map_or("", |(_, name)| name)
    }
}

/// Whom a session acts as, by unique id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", deny_unknown_fields)]
pub(crate) enum Who {
    /// `AssumeRole`.
    Role {
        role: String,
        name: String,
        #[serde(default)]
        chained: bool,
    },
    /// `GetSessionToken`, by a user (or the root user: `None`).
    SessionToken { user: Option<String> },
    /// `GetFederationToken`, started by a user (or the root user: `None`).
    Federated { user: Option<String>, name: String },
    /// MinIO's `AssumeRole` without a role.
    User { user: String },
}

impl Claims {
    pub(crate) fn new(who: Who, iat: i64, exp: i64) -> Self {
        Self {
            v: VERSION,
            who,
            iat,
            exp,
            policies: Vec::new(),
            tags: Vec::new(),
            transitive: Vec::new(),
            source: None,
            web: None,
        }
    }
}

/// Why a request's credentials weren't accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No such access key, or not an active one.
    #[error("The AWS access key Id you provided does not exist in our records.")]
    UnknownKey,
    /// A temporary key without its token, a token that isn't its key's, or a token
    /// with a long-term key.
    #[error("The provided token is malformed or otherwise invalid.")]
    InvalidToken,
    /// The session has expired.
    #[error("The provided token has expired.")]
    ExpiredToken,
    /// The user or role the session acts as is gone.
    #[error("The session's user or role no longer exists.")]
    Revoked,
}

/// Whether `id` is shaped like a temporary access key id: `TSIA` and 16 base32
/// characters.
pub(crate) fn is_session_key(id: &str) -> bool {
    id.len() == 20
        && id.starts_with(PREFIX)
        && id[PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

/// New temporary credentials.
pub struct Issued {
    /// The access key id.
    pub access_key: String,
    /// The secret key.
    pub secret: Zeroizing<String>,
    /// The session token.
    pub token: String,
    /// When they expire, in seconds since the Unix epoch.
    pub expires: i64,
    /// How much of the largest token theirs takes, in percent: AWS's
    /// `SessionTokenUtilization` (and the `PackedPolicySize` it replaces).
    pub utilization: usize,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("access_key", &self.access_key)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

impl Iam {
    /// The secret of an access key, to check a signature with: an active key's, the
    /// root's, or a temporary key's (whose token is checked by [`Self::identify`]).
    #[must_use]
    pub fn secret(&self, access_key: &str) -> Option<Arc<Zeroizing<String>>> {
        if is_session_key(access_key) {
            return Some(Arc::new(self.session_secret(access_key)));
        }
        self.credential(access_key).map(|c| c.secret)
    }

    /// Who signed a request with `access_key` and, for temporary credentials, the
    /// session `token` sent with it.
    pub fn identify(
        &self,
        access_key: &str,
        token: Option<&str>,
    ) -> Result<Arc<Identity>, AuthError> {
        self.identify_at(access_key, token, now_seconds())
    }

    pub(crate) fn identify_at(
        &self,
        access_key: &str,
        token: Option<&str>,
        now: i64,
    ) -> Result<Arc<Identity>, AuthError> {
        if !is_session_key(access_key) {
            if token.is_some() {
                return Err(AuthError::InvalidToken);
            }
            return self
                .credential(access_key)
                .map(|c| c.identity)
                .ok_or(AuthError::UnknownKey);
        }
        let token = token.ok_or(AuthError::InvalidToken)?;
        let snapshot = self.snapshot();
        let cached = snapshot.cached_session(access_key, token);
        let identity = if let Some(identity) = cached {
            identity
        } else {
            let claims = self
                .open_session(access_key, token)
                .ok_or(AuthError::InvalidToken)?;
            snapshot
                .add_session(access_key, token, &claims)
                .ok_or(AuthError::Revoked)?
        };
        let session = identity
            .session()
            .expect("a temporary key's identity is a session's");
        if now >= session.expires() {
            return Err(AuthError::ExpiredToken);
        }
        Ok(identity)
    }

    /// The claims `token` seals for `access_key`, if it's a genuine token of that key.
    fn open_session(&self, access_key: &str, token: &str) -> Option<Claims> {
        let sealed = STANDARD.decode(token).ok()?;
        let plain = self
            .tokens
            .open_token(access_key.as_bytes(), &sealed)
            .ok()?;
        serde_json::from_slice::<Claims>(&plain)
            .ok()
            .filter(|claims| claims.v == VERSION)
    }

    fn session_secret(&self, access_key: &str) -> Zeroizing<String> {
        let mac = self.tokens.session_secret(access_key.as_bytes());
        Zeroizing::new(STANDARD.encode(&mac[..30]))
    }

    /// New credentials for `claims`.
    pub(crate) fn issue(&self, claims: &Claims) -> Result<Issued, crate::IamError> {
        let plain = Zeroizing::new(serde_json::to_vec(claims).expect("claims serialize"));
        let access_key = ids::session_key();
        let sealed = self.tokens.seal_token(access_key.as_bytes(), &plain);
        if sealed.len() > PACKED_LIMIT {
            return Err(crate::IamError::PackedPolicyTooLarge);
        }
        Ok(Issued {
            secret: self.session_secret(&access_key),
            token: STANDARD.encode(&sealed),
            expires: claims.exp,
            utilization: sealed.len() * 100 / PACKED_LIMIT,
            access_key,
        })
    }
}

/// Seconds since the Unix epoch.
pub(crate) fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;
    use crate::RootKey;

    async fn iam() -> (tempfile::TempDir, Iam) {
        let dir = tempfile::tempdir().unwrap();
        let kms = teifs_crypto::LocalKms::open(dir.path().join("keyring.json")).unwrap();
        let root = RootKey {
            access_key: "TFROOTKEY".into(),
            secret: Zeroizing::new("root-secret".into()),
        };
        let iam = Iam::open(&dir.path().join("system.db"), "d", &kms, Some(root))
            .await
            .unwrap();
        (dir, iam)
    }

    #[test]
    fn temporary_keys_have_their_own_shape() {
        assert!(is_session_key("TSIAABCDEFGHIJKLMN27"));
        for other in [
            "TSIAABCDEFGHIJKLMN2",
            "TSIAABCDEFGHIJKLMN277",
            "TSIAABCDEFGHIJKLMN28",
            "TSIAabcdefghijklmn27",
            "AKIAABCDEFGHIJKLMN27",
            "TFROOTKEY",
        ] {
            assert!(!is_session_key(other), "{other}");
        }
    }

    #[tokio::test]
    async fn secrets_are_derived_per_key_and_tokens_are_versioned() {
        let (_dir, iam) = iam().await;
        let root = iam.credential("TFROOTKEY").unwrap().identity;
        assert_eq!(
            iam.secret("TFROOTKEY").unwrap().as_str(),
            "root-secret",
            "a long-term key's own secret"
        );
        assert!(iam.secret("AKIANOSUCHKEY0000000").is_none());
        let a = iam.secret("TSIAABCDEFGHIJKLMN27").unwrap();
        assert_eq!(a, iam.secret("TSIAABCDEFGHIJKLMN27").unwrap());
        assert_ne!(a, iam.secret("TSIAABCDEFGHIJKLMN26").unwrap());
        assert_eq!(a.len(), 40);

        let now = now_seconds();
        let claims = Claims::new(Who::SessionToken { user: None }, now, now + 900);
        let issued = iam.issue(&claims).unwrap();
        assert_eq!(
            iam.secret(&issued.access_key).unwrap().as_str(),
            &*issued.secret
        );
        let session = iam
            .identify(&issued.access_key, Some(&issued.token))
            .unwrap();
        assert!(session.is_root());
        assert_eq!(session.principal(), root.principal());
        assert_eq!(session.session().unwrap().expires(), now + 900);
        assert_eq!(
            session.session().unwrap().issued(),
            teifs_policy::Date::from_unix_seconds(now)
        );
        // A token of claims in another version isn't read.
        let mut future = claims;
        future.v = VERSION + 1;
        let issued = iam.issue(&future).unwrap();
        assert_eq!(
            iam.identify(&issued.access_key, Some(&issued.token))
                .unwrap_err(),
            AuthError::InvalidToken
        );
    }
}
