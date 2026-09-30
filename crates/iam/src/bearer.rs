//! Bearer tokens for Prometheus, which can't sign requests: a JWT (HS256) naming an
//! access key, signed with that key's secret, as `mc admin prometheus generate` makes
//! them for `MinIO`. The key's current policies decide what the token may do, so
//! deactivating or deleting the key revokes it.

use std::sync::Arc;

use aws_lc_rs::hmac;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{AuthError, Iam, Identity, sessions::is_session_key};

/// The one header a token has.
const HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;
/// Who issues tokens.
const ISSUER: &str = "teifs";
/// What they're for: a token made for scrapes is good for nothing else.
const AUDIENCE: &str = "teifs-metrics";
/// The longest token accepted: more than any access key, signature and claims need.
const MAX_LEN: usize = 1024;

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
}

fn sign(secret: &str, message: &str) -> hmac::Tag {
    hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
        message.as_bytes(),
    )
}

/// A token for scraping metrics as `access_key`, signed with its `secret`, good until
/// `expires` (seconds since the Unix epoch) or, without it, until the key is revoked.
#[must_use]
pub fn metrics_token(access_key: &str, secret: &str, expires: Option<i64>) -> Zeroizing<String> {
    let claims = Claims {
        sub: access_key.to_owned(),
        iss: ISSUER.to_owned(),
        aud: AUDIENCE.to_owned(),
        exp: expires,
    };
    let claims = serde_json::to_vec(&claims).expect("claims serialize");
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature = URL_SAFE_NO_PAD.encode(sign(secret, &message));
    Zeroizing::new(format!("{message}.{signature}"))
}

impl Iam {
    /// Who a metrics token was made for, once its signature, issuer, audience and expiry
    /// are checked; only active long-term keys make them.
    pub fn identify_metrics_token(&self, token: &str) -> Result<Arc<Identity>, AuthError> {
        identify(self, token, crate::sessions::now_seconds())
    }
}

fn identify(iam: &Iam, token: &str, now: i64) -> Result<Arc<Identity>, AuthError> {
    if token.len() > MAX_LEN {
        return Err(AuthError::InvalidToken);
    }
    let (message, signature) = token.rsplit_once('.').ok_or(AuthError::InvalidToken)?;
    let (header, claims) = message.split_once('.').ok_or(AuthError::InvalidToken)?;
    // Only the header this module writes: no other algorithm is ever considered.
    if URL_SAFE_NO_PAD.decode(header).ok().as_deref() != Some(HEADER.as_bytes()) {
        return Err(AuthError::InvalidToken);
    }
    let claims: Claims = URL_SAFE_NO_PAD
        .decode(claims)
        .ok()
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or(AuthError::InvalidToken)?;
    if claims.iss != ISSUER || claims.aud != AUDIENCE || is_session_key(&claims.sub) {
        return Err(AuthError::InvalidToken);
    }
    let credential = iam.credential(&claims.sub).ok_or(AuthError::UnknownKey)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AuthError::InvalidToken)?;
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, credential.secret.as_bytes()),
        message.as_bytes(),
        &signature,
    )
    .map_err(|_| AuthError::InvalidToken)?;
    if claims.exp.is_some_and(|exp| now >= exp) {
        return Err(AuthError::ExpiredToken);
    }
    Ok(credential.identity)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;
    use crate::RootKey;

    /// An IAM with a user `metrics` and an access key of theirs.
    async fn iam() -> (tempfile::TempDir, Iam, String, Zeroizing<String>) {
        let dir = tempfile::tempdir().unwrap();
        let kms = teifs_crypto::LocalKms::open(dir.path().join("keyring.json")).unwrap();
        let root = RootKey {
            access_key: "TFROOTKEY".into(),
            secret: Zeroizing::new("root-secret".into()),
        };
        let iam = Iam::open(&dir.path().join("system.db"), "d", &kms, Some(root))
            .await
            .unwrap();
        iam.create_user("metrics", None, &[], None).unwrap();
        let key = iam.create_access_key("metrics").unwrap();
        (dir, iam, key.info.id, key.secret)
    }

    #[tokio::test]
    async fn a_token_names_its_key_until_it_expires_or_the_key_goes() {
        let (_dir, iam, key, secret) = iam().await;
        let token = metrics_token(&key, &secret, Some(2_000));
        let identity = identify(&iam, &token, 1_999).unwrap();
        assert_eq!(
            identity.principal(),
            iam.identify(&key, None).unwrap().principal()
        );
        assert!(matches!(
            identify(&iam, &token, 2_000),
            Err(AuthError::ExpiredToken)
        ));
        let forever = metrics_token(&key, &secret, None);
        assert!(identify(&iam, &forever, i64::MAX).is_ok());
        let root = metrics_token("TFROOTKEY", "root-secret", None);
        assert!(identify(&iam, &root, 0).unwrap().is_root());
        iam.delete_access_key("metrics", &key).unwrap();
        assert!(matches!(
            identify(&iam, &forever, 0),
            Err(AuthError::UnknownKey)
        ));
    }

    #[tokio::test]
    async fn forged_and_foreign_tokens_are_refused() {
        let (_dir, iam, key, secret) = iam().await;
        let refused =
            |token: &str| matches!(identify(&iam, token, 0), Err(AuthError::InvalidToken));
        assert!(refused(&metrics_token(&key, "not-the-secret", None)));
        let token = metrics_token(&key, &secret, None);
        let parts: Vec<&str> = token.split('.').collect();
        let encode = |json: &str| URL_SAFE_NO_PAD.encode(json);
        // Signed as another algorithm, or claims changed after signing.
        let none = format!("{}.{}.", encode(r#"{"alg":"none","typ":"JWT"}"#), parts[1]);
        assert!(refused(&none));
        let longer = encode(&format!(
            r#"{{"sub":"{key}","iss":"teifs","aud":"teifs-metrics","exp":1}}"#
        ));
        assert!(refused(&format!("{}.{longer}.{}", parts[0], parts[2])));
        // Signed right, but for another use, by another issuer, or with a temporary key.
        for claims in [
            format!(r#"{{"sub":"{key}","iss":"teifs","aud":"s3"}}"#),
            format!(r#"{{"sub":"{key}","iss":"minio","aud":"teifs-metrics"}}"#),
            r#"{"sub":"TSIAABCDEFGHIJKLMN27","iss":"teifs","aud":"teifs-metrics"}"#.to_owned(),
        ] {
            let message = format!("{}.{}", parts[0], encode(&claims));
            let signature = URL_SAFE_NO_PAD.encode(sign(&secret, &message));
            assert!(refused(&format!("{message}.{signature}")));
        }
        // Signed right, but under a header this module doesn't write, or too long.
        let signed = |header: &str, claims: &str| {
            let message = format!("{}.{}", encode(header), encode(claims));
            let signature = URL_SAFE_NO_PAD.encode(sign(&secret, &message));
            format!("{message}.{signature}")
        };
        let claims = format!(r#"{{"sub":"{key}","iss":"teifs","aud":"teifs-metrics"}}"#);
        assert!(identify(&iam, &signed(HEADER, &claims), 0).is_ok());
        assert!(refused(&signed(r#"{"alg":"HS512","typ":"JWT"}"#, &claims)));
        let padded = format!(
            r#"{{"sub":"{key}","iss":"teifs","aud":"teifs-metrics","pad":"{}"}}"#,
            "x".repeat(MAX_LEN)
        );
        assert!(refused(&signed(HEADER, &padded)));
        for malformed in ["", "a.b", "a.b.c.d"] {
            assert!(refused(malformed));
        }
    }
}
