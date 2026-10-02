//! `MinIO`'s `revoke-tokens`: ending a user's temporary credentials before they expire.
//! Sessions are kept nowhere, so a revocation records when: a session of the user issued
//! then or before is refused, all of them or those of one token revoke type.

use teifs_meta::{IamWrite, RevocationRow};

use super::minio::{MinioError, user_named};
use crate::{
    Iam, Identity, Session, SessionKind, ldap,
    sessions::{ROOT_SUBJECT, ldap_subject, user_subject},
};

/// The longest a session lasts; a revocation older than it ends nothing more.
const LONGEST_SESSION_MS: i64 = 31_536_000_000;

/// The user whose temporary credentials `revoke-tokens` ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionParent {
    /// The root user.
    Root,
    /// A user, by name.
    User(String),
    /// A directory user, by DN.
    Ldap(String),
}

impl Iam {
    /// The user `identity` is, or acts for: its own temporary credentials' parent, as
    /// `MinIO` has it. None for sessions `revoke-tokens` doesn't reach (roles', web
    /// identities' and their service accounts', federated users').
    #[must_use]
    pub fn session_parent(&self, identity: &Identity) -> Option<SessionParent> {
        if identity.is_root() {
            return Some(SessionParent::Root);
        }
        let session = identity.session();
        if let Some(user) = session.and_then(Session::ldap_user) {
            return Some(SessionParent::Ldap(user.dn.to_owned()));
        }
        if session.and_then(Session::openid_user).is_some() {
            return None;
        }
        let kind = session.map(Session::kind);
        if !matches!(
            kind,
            None | Some(SessionKind::User | SessionKind::SessionToken | SessionKind::Service)
        ) {
            return None;
        }
        match identity.entity() {
            Some((_, id)) => {
                self.view(|s| s.users.get(id).map(|u| SessionParent::User(u.name.clone())))
            }
            None if kind == Some(SessionKind::Service) => Some(SessionParent::Root),
            None => None,
        }
    }

    /// Ends `parent`'s temporary credentials issued until now: all of them, or only
    /// those of `revoke_type`. A user that doesn't exist has none, as on `MinIO`.
    ///
    /// # Errors
    ///
    /// A DN that doesn't parse, or the database refusing the change.
    pub fn revoke_sessions(
        &self,
        parent: &SessionParent,
        revoke_type: Option<&str>,
    ) -> std::result::Result<(), MinioError> {
        self.change(|d| {
            let subject = match parent {
                SessionParent::Root => ROOT_SUBJECT.to_owned(),
                SessionParent::User(name) => match user_named(&d.state, name) {
                    Ok(user) => user_subject(&user.id),
                    Err(_) => return Ok(()),
                },
                SessionParent::Ldap(dn) => {
                    ldap_subject(&ldap::normalize(dn).map_err(|_| MinioError::NoSuchUser)?)
                }
            };
            let stale: Vec<(String, String)> = d
                .state
                .revocations
                .iter()
                .filter(|(_, cutoff)| cutoff.saturating_add(LONGEST_SESSION_MS) < d.now)
                .map(|(key, _)| key.clone())
                .collect();
            for key in stale {
                d.state.revocations.remove(&key);
                d.write(IamWrite::DeleteRevocation(key.0, key.1));
            }
            let row = RevocationRow {
                subject,
                revoke_type: revoke_type.unwrap_or_default().to_owned(),
                cutoff_ms: d.now,
            };
            d.state.revocations.insert(
                (row.subject.clone(), row.revoke_type.clone()),
                row.cutoff_ms,
            );
            d.write(IamWrite::PutRevocation(row));
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        AuthError, IamError, MinioUserChange, RootKey,
        sessions::{Claims, Who, now_seconds},
    };

    async fn iam(dir: &tempfile::TempDir) -> Iam {
        let kms = teifs_crypto::LocalKms::open(dir.path().join("keyring.json")).unwrap();
        let root = RootKey {
            access_key: "TFROOTKEY".into(),
            secret: Zeroizing::new("root-secret".into()),
        };
        Iam::open(&dir.path().join("system.db"), "d", &kms, Some(root))
            .await
            .unwrap()
    }

    /// A session of `who` with `revoke_type`: its access key and token.
    fn session(iam: &Iam, who: Who, revoke_type: Option<&str>) -> (String, String) {
        let mut claims = Claims::issued_now(who, 900);
        claims.revoke_type = revoke_type.map(str::to_owned);
        let issued = iam.issue(&claims).unwrap();
        (issued.access_key, issued.token)
    }

    fn works(iam: &Iam, (key, token): &(String, String)) -> Result<(), AuthError> {
        iam.identify(key, Some(token)).map(|_| ())
    }

    /// Past the millisecond a revocation was made in.
    fn later() {
        std::thread::sleep(std::time::Duration::from_millis(3));
    }

    #[tokio::test]
    async fn a_revocation_ends_the_sessions_issued_until_then() {
        let dir = tempfile::tempdir().unwrap();
        let iam = iam(&dir).await;
        let change = MinioUserChange {
            secret: Some("alice-secret-key"),
            enabled: Some(true),
            policies: None,
        };
        iam.minio_set_user("alice", change).unwrap();
        let id = iam.view(|s| s.user_named("alice").unwrap().id.clone());
        let user = || Who::User { user: id.clone() };
        let app = session(&iam, user(), Some("app"));
        let web = session(&iam, user(), Some("web"));
        let plain = session(&iam, user(), None);
        // A token from before tokens said their millisecond.
        let now = now_seconds();
        let old = iam
            .issue(&Claims::new(user(), now, now + 900))
            .map(|i| (i.access_key, i.token))
            .unwrap();
        let root = session(&iam, Who::SessionToken { user: None }, None);

        let alice = SessionParent::User("alice".into());
        iam.revoke_sessions(&alice, Some("app")).unwrap();
        assert_eq!(works(&iam, &app), Err(AuthError::Revoked));
        for other in [&web, &plain, &old, &root] {
            assert_eq!(works(&iam, other), Ok(()));
        }
        let identity = iam.identify(&web.0, Some(&web.1)).unwrap();
        assert_eq!(identity.session().unwrap().revoke_type(), Some("web"));
        assert_eq!(iam.session_parent(&identity), Some(alice.clone()));

        iam.revoke_sessions(&alice, None).unwrap();
        for ended in [&web, &plain, &old] {
            assert_eq!(works(&iam, ended), Err(AuthError::Revoked), "{}", ended.0);
        }
        assert_eq!(works(&iam, &root), Ok(()));
        later();
        let after = session(&iam, user(), Some("app"));
        assert_eq!(works(&iam, &after), Ok(()));

        iam.revoke_sessions(&SessionParent::Root, None).unwrap();
        assert_eq!(works(&iam, &root), Err(AuthError::Revoked));
        // Someone who isn't there has nothing to end.
        iam.revoke_sessions(&SessionParent::User("nobody".into()), None)
            .unwrap();

        // Revocations last across restarts.
        drop(iam);
        let iam = iam_reopened(&dir).await;
        assert_eq!(works(&iam, &web), Err(AuthError::Revoked));
        assert_eq!(works(&iam, &after), Ok(()));
    }

    async fn iam_reopened(dir: &tempfile::TempDir) -> Iam {
        iam(dir).await
    }

    #[tokio::test]
    async fn revocations_older_than_any_session_are_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let iam = iam(&dir).await;
        let old = ("user:gone".to_owned(), String::new());
        iam.change(|d| {
            d.state.revocations.insert(old.clone(), 1);
            d.write(IamWrite::PutRevocation(RevocationRow {
                subject: old.0.clone(),
                revoke_type: String::new(),
                cutoff_ms: 1,
            }));
            Ok::<_, IamError>(())
        })
        .unwrap();
        iam.revoke_sessions(&SessionParent::Root, Some("app"))
            .unwrap();
        let kept: Vec<_> = iam.view(|s| s.revocations.keys().cloned().collect());
        assert_eq!(kept, [(ROOT_SUBJECT.to_owned(), "app".to_owned())]);
        drop(iam);
        let iam = iam_reopened(&dir).await;
        assert_eq!(iam.view(|s| s.revocations.len()), 1);
    }

    #[tokio::test]
    async fn the_parent_of_root_and_of_sessions_revoke_tokens_does_not_reach() {
        let dir = tempfile::tempdir().unwrap();
        let iam = iam(&dir).await;
        let root = iam.credential("TFROOTKEY").unwrap().identity;
        assert_eq!(iam.session_parent(&root), Some(SessionParent::Root));
        let custom = session(
            &iam,
            Who::Custom {
                user: "plugin-user".into(),
                policies: Vec::new(),
            },
            None,
        );
        let identity = iam.identify(&custom.0, Some(&custom.1)).unwrap();
        assert_eq!(iam.session_parent(&identity), None);
    }
}
