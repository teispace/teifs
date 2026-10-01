//! `AssumeRoleWithLDAPIdentity` end to end in IAM, against [`super::fake::FakeLdap`]:
//! who gets a session, what it may do as mappings and the directory change, and what's
//! refused.

use std::sync::Arc;

use teifs_crypto::LocalKms;
use teifs_policy::{Context, Date};
use zeroize::Zeroizing;

use super::fake::{FakeLdap, group, person};
use crate::{AuthError, Call, Iam, Identity, LdapEntity, Reply, RootKey};

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;
const HOME: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*",
  "Resource":"arn:aws:s3:::home/${ldap:username}/*"}]}"#;
const DILLON: &str = "uid=dillon,ou=people,dc=min,dc=io";
const LIZA: &str = "uid=liza,ou=people,dc=min,dc=io";
const PROJECT_A: &str = "cn=projecta,ou=groups,dc=min,dc=io";
const PROJECT_B: &str = "cn=projectb,ou=groups,dc=min,dc=io";

struct Setup {
    dir: tempfile::TempDir,
    iam: Iam,
    fake: FakeLdap,
}

async fn open(dir: &std::path::Path, fake: &FakeLdap) -> Iam {
    let kms = LocalKms::open(dir.join("keyring.json")).unwrap();
    let root = RootKey {
        access_key: "TFROOTKEY".into(),
        secret: Zeroizing::new("root-secret".into()),
    };
    Iam::open(&dir.join("system.db"), "drive-1", &kms, Some(root))
        .await
        .unwrap()
        .with_ldap(fake.directory())
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeLdap::start().await;
    let iam = open(dir.path(), &fake).await;
    iam.create_policy("read-photos", None, None, READ_PHOTOS, &[])
        .unwrap();
    iam.create_policy("home", None, None, HOME, &[]).unwrap();
    Setup { dir, iam, fake }
}

/// Asks for an LDAP session, unsigned.
async fn sign_in(iam: &Iam, form: &[(&str, &str)]) -> Reply {
    let mut body = form_urlencoded::Serializer::new(String::new());
    body.append_pair("Action", "AssumeRoleWithLDAPIdentity")
        .append_pair("Version", "2011-06-15");
    for (name, value) in form {
        body.append_pair(name, value);
    }
    let body = body.finish();
    assert!(Iam::proves_itself(body.as_bytes()));
    let identity = Identity::anonymous();
    let context = Context::new(identity.principal().clone(), Date::now());
    iam.serve_self_proving(&Call {
        identity: &identity,
        context: &context,
        body: body.as_bytes(),
        request_id: "test",
    })
    .await
}

fn element<'a>(body: &'a str, name: &str) -> &'a str {
    let start = body.find(&format!("<{name}>")).unwrap() + name.len() + 2;
    let end = start + body[start..].find(&format!("</{name}>")).unwrap();
    &body[start..end]
}

/// The session `reply` gave: its access key and token.
fn session(reply: &Reply) -> (String, String) {
    assert_eq!(reply.status, 200, "{}", reply.body);
    (
        element(&reply.body, "AccessKeyId").to_owned(),
        element(&reply.body, "SessionToken").to_owned(),
    )
}

async fn signed_in(iam: &Iam, user: &str) -> (String, String) {
    let password = format!("{user}-password");
    session(&sign_in(iam, &[("LDAPUsername", user), ("LDAPPassword", &password)]).await)
}

fn identity(iam: &Iam, (key, token): &(String, String)) -> Result<Arc<Identity>, AuthError> {
    iam.identify(key, Some(token))
}

fn allows(iam: &Iam, session: &(String, String), action: &str, resource: &str) -> bool {
    let identity = identity(iam, session).unwrap();
    identity.allows(&identity.context(Date::now()), action, resource)
}

fn refusal(reply: &Reply) -> (u16, String, String) {
    (
        reply.status,
        element(&reply.body, "Code").to_owned(),
        element(&reply.body, "Message").to_owned(),
    )
}

#[tokio::test]
async fn a_user_without_policies_is_refused() {
    let Setup { iam, .. } = setup().await;
    let reply = sign_in(
        &iam,
        &[
            ("LDAPUsername", "dillon"),
            ("LDAPPassword", "dillon-password"),
        ],
    )
    .await;
    assert_eq!(
        refusal(&reply),
        (
            400,
            "InvalidParameterValue".into(),
            format!(
                "expecting a policy to be set for user `{DILLON}` or one of their groups: \
                 `{PROJECT_A}`,`{PROJECT_B}` - rejecting this request"
            )
        )
    );
}

#[tokio::test]
async fn sessions_get_the_policies_of_the_user_and_its_groups() {
    let Setup { iam, .. } = setup().await;
    iam.map_ldap_policies(PROJECT_A, LdapEntity::Group, &["read-photos".into()], true)
        .unwrap();
    let dillon = signed_in(&iam, "dillon").await;
    let who = identity(&iam, &dillon).unwrap();
    assert_eq!(
        who.principal().arn(),
        Some("arn:aws:sts::".to_owned() + &iam.account() + ":federated-user/dillon").as_deref()
    );
    assert!(allows(
        &iam,
        &dillon,
        "s3:GetObject",
        "arn:aws:s3:::photos/a"
    ));
    assert!(!allows(
        &iam,
        &dillon,
        "s3:PutObject",
        "arn:aws:s3:::photos/a"
    ));
    // ${ldap:username} names the user.
    iam.map_ldap_policies(DILLON, LdapEntity::User, &["home".into()], true)
        .unwrap();
    assert!(allows(
        &iam,
        &dillon,
        "s3:PutObject",
        "arn:aws:s3:::home/dillon/a"
    ));
    assert!(!allows(
        &iam,
        &dillon,
        "s3:PutObject",
        "arn:aws:s3:::home/liza/a"
    ));
    // A change reaches live sessions.
    iam.map_ldap_policies(PROJECT_A, LdapEntity::Group, &["read-photos".into()], false)
        .unwrap();
    assert!(!allows(
        &iam,
        &dillon,
        "s3:GetObject",
        "arn:aws:s3:::photos/a"
    ));
    assert!(allows(
        &iam,
        &dillon,
        "s3:PutObject",
        "arn:aws:s3:::home/dillon/a"
    ));
    // Its context names it.
    let context = identity(&iam, &dillon).unwrap().context(Date::now());
    let policy = teifs_policy::Policy::parse(
        &format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:*",
              "Resource":"*","Condition":{{"StringEquals":{{"ldap:user":"{DILLON}",
              "ldap:username":"dillon"}},"ForAnyValue:StringEquals":{{"ldap:groups":"{PROJECT_B}"}}}}}}]}}"#
        ),
        teifs_policy::Kind::Identity,
    )
    .unwrap();
    assert!(
        teifs_policy::evaluate(
            &teifs_policy::Policies {
                identity: &[&policy],
                ..teifs_policy::Policies::default()
            },
            &teifs_policy::Request {
                action: "s3:GetObject",
                resource: "arn:aws:s3:::x/y",
                context: &context,
            },
        )
        .is_allowed()
    );
}

#[tokio::test]
async fn session_policies_and_durations_are_minios() {
    let Setup { iam, .. } = setup().await;
    iam.map_ldap_policies(
        DILLON,
        LdapEntity::User,
        &["read-photos".into(), "home".into()],
        true,
    )
    .unwrap();
    let narrow = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let reply = sign_in(
        &iam,
        &[
            ("LDAPUsername", "dillon"),
            ("LDAPPassword", "dillon-password"),
            ("Policy", narrow),
            ("DurationSeconds", "31536000"),
        ],
    )
    .await;
    let dillon = session(&reply);
    assert!(allows(
        &iam,
        &dillon,
        "s3:GetObject",
        "arn:aws:s3:::photos/a"
    ));
    assert!(!allows(
        &iam,
        &dillon,
        "s3:PutObject",
        "arn:aws:s3:::home/dillon/a"
    ));
    let expires = identity(&iam, &dillon)
        .unwrap()
        .session()
        .unwrap()
        .expires();
    let year = crate::sessions::now_seconds() + 31_536_000;
    assert!((year - 5..=year).contains(&expires), "{expires}");
    let hour = identity(&iam, &signed_in(&iam, "dillon").await)
        .unwrap()
        .session()
        .unwrap()
        .expires();
    let expected = crate::sessions::now_seconds() + 3600;
    assert!((expected - 5..=expected).contains(&hour), "{hour}");
    for seconds in ["899", "31536001", "x"] {
        let reply = sign_in(
            &iam,
            &[
                ("LDAPUsername", "dillon"),
                ("LDAPPassword", "dillon-password"),
                ("DurationSeconds", seconds),
            ],
        )
        .await;
        assert_eq!(reply.status, 400, "{seconds}: {}", reply.body);
    }
    // As every action that issues credentials, a token at least as long as asked.
    let padded = sign_in(
        &iam,
        &[
            ("LDAPUsername", "dillon"),
            ("LDAPPassword", "dillon-password"),
            ("MinimumSessionTokenSize", "3000"),
        ],
    )
    .await;
    assert!(session(&padded).1.len() >= 3000);
    let too_long = sign_in(
        &iam,
        &[
            ("LDAPUsername", "dillon"),
            ("LDAPPassword", "dillon-password"),
            ("MinimumSessionTokenSize", "5000"),
        ],
    )
    .await;
    assert_eq!(too_long.status, 400, "{}", too_long.body);
}

#[tokio::test]
async fn bad_sign_ins_are_refused() {
    let Setup { iam, fake, dir } = setup().await;
    iam.map_ldap_policies(DILLON, LdapEntity::User, &["home".into()], true)
        .unwrap();
    let empty = sign_in(&iam, &[("LDAPUsername", "dillon"), ("LDAPPassword", "")]).await;
    assert_eq!(
        refusal(&empty),
        (
            400,
            "MissingParameter".into(),
            "LDAPUsername and LDAPPassword cannot be empty".into()
        )
    );
    let wrong = sign_in(
        &iam,
        &[("LDAPUsername", "dillon"), ("LDAPPassword", "nope")],
    )
    .await;
    assert_eq!(
        refusal(&wrong),
        (
            400,
            "InvalidParameterValue".into(),
            "LDAP server error: the LDAP user name or password is wrong".into()
        )
    );
    let bad_policy = sign_in(
        &iam,
        &[
            ("LDAPUsername", "dillon"),
            ("LDAPPassword", "dillon-password"),
            ("Policy", "{"),
        ],
    )
    .await;
    assert_eq!(refusal(&bad_policy).1, "MalformedPolicyDocument");
    // Without a directory.
    drop(iam);
    let kms = LocalKms::open(dir.path().join("keyring.json")).unwrap();
    let plain = Iam::open(&dir.path().join("system.db"), "drive-1", &kms, None)
        .await
        .unwrap();
    let reply = sign_in(
        &plain,
        &[
            ("LDAPUsername", "dillon"),
            ("LDAPPassword", "dillon-password"),
        ],
    )
    .await;
    assert_eq!(refusal(&reply).1, "InvalidParameterValue");
    assert!(
        refusal(&reply).2.contains("set up on this server"),
        "{}",
        reply.body
    );
    drop(fake);
}

#[tokio::test]
async fn the_directory_check_refreshes_groups_and_revokes_gone_users() {
    let Setup { iam, fake, dir } = setup().await;
    iam.map_ldap_policies(PROJECT_B, LdapEntity::Group, &["read-photos".into()], true)
        .unwrap();
    let liza = signed_in(&iam, "liza").await;
    assert!(allows(&iam, &liza, "s3:GetObject", "arn:aws:s3:::photos/a"));
    // Liza leaves the group.
    fake.remove(PROJECT_B);
    fake.add(group("projectb", &["dillon"]));
    iam.check_ldap_users().await.unwrap();
    assert!(!allows(
        &iam,
        &liza,
        "s3:GetObject",
        "arn:aws:s3:::photos/a"
    ));
    // And comes back.
    fake.remove(PROJECT_B);
    fake.add(group("projectb", &["dillon", "liza"]));
    iam.check_ldap_users().await.unwrap();
    assert!(allows(&iam, &liza, "s3:GetObject", "arn:aws:s3:::photos/a"));
    // Liza is removed from the directory: her sessions are revoked, also after a
    // restart.
    fake.remove(LIZA);
    iam.check_ldap_users().await.unwrap();
    assert_eq!(identity(&iam, &liza).err(), Some(AuthError::Revoked));
    drop(iam);
    let iam = open(dir.path(), &fake).await;
    assert_eq!(identity(&iam, &liza).err(), Some(AuthError::Revoked));
    // A new account of the same name gets new sessions; the old stay revoked.
    fake.add(person("liza", "people"));
    let again = signed_in(&iam, "liza").await;
    assert!(allows(
        &iam,
        &again,
        "s3:GetObject",
        "arn:aws:s3:::photos/a"
    ));
    assert_eq!(identity(&iam, &liza).err(), Some(AuthError::Revoked));
    // An unreachable directory changes nothing.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let mut settings = fake.settings();
    settings.server = address.to_string();
    let iam = {
        drop(iam);
        let kms = LocalKms::open(dir.path().join("keyring.json")).unwrap();
        Iam::open(&dir.path().join("system.db"), "drive-1", &kms, None)
            .await
            .unwrap()
            .with_ldap(super::Directory::new(settings).unwrap())
    };
    iam.check_ldap_users().await.unwrap();
    assert!(allows(
        &iam,
        &again,
        "s3:GetObject",
        "arn:aws:s3:::photos/a"
    ));
}

#[tokio::test]
async fn mappings_are_kept_listed_and_guard_their_policies() {
    let Setup { iam, fake, dir } = setup().await;
    let both = ["read-photos".to_owned(), "home".to_owned()];
    let change = iam
        .map_ldap_policies(PROJECT_A, LdapEntity::Group, &both, true)
        .unwrap();
    assert_eq!(change.changed, ["home", "read-photos"]);
    assert_eq!(change.policies, ["home", "read-photos"]);
    let again = iam
        .map_ldap_policies(PROJECT_A, LdapEntity::Group, &both[..1], true)
        .unwrap();
    assert!(again.changed.is_empty());
    assert_eq!(
        iam.map_ldap_policies(PROJECT_A, LdapEntity::User, &both[..1], true)
            .unwrap_err()
            .code(),
        "InvalidInput"
    );
    assert_eq!(
        iam.map_ldap_policies(DILLON, LdapEntity::User, &["nothing".into()], true)
            .unwrap_err()
            .code(),
        "NoSuchEntity"
    );
    assert_eq!(
        iam.map_ldap_policies(DILLON, LdapEntity::User, &[], true)
            .unwrap_err()
            .code(),
        "InvalidInput"
    );
    let arn = format!("arn:aws:iam::{}:policy/home", iam.account());
    iam.map_ldap_policies(DILLON, LdapEntity::User, std::slice::from_ref(&arn), true)
        .unwrap();
    assert_eq!(
        iam.delete_policy(&arn).unwrap_err().code(),
        "DeleteConflict"
    );
    // Kept across a restart.
    drop(iam);
    let iam = open(dir.path(), &fake).await;
    let all = iam.ldap_policies(None).unwrap();
    assert_eq!(
        all.iter()
            .map(|m| (m.entity, m.dn.as_str(), m.policies.join(",")))
            .collect::<Vec<_>>(),
        [
            (LdapEntity::User, DILLON, "home".to_owned()),
            (LdapEntity::Group, PROJECT_A, "home,read-photos".to_owned()),
        ]
    );
    assert_eq!(iam.ldap_policies(Some(DILLON)).unwrap().len(), 1);
    // Removing the last policy removes the mapping.
    iam.map_ldap_policies(DILLON, LdapEntity::User, &["home".into()], false)
        .unwrap();
    iam.map_ldap_policies(PROJECT_A, LdapEntity::Group, &both, false)
        .unwrap();
    assert!(iam.ldap_policies(None).unwrap().is_empty());
    iam.delete_policy(&arn).unwrap();
}

#[tokio::test]
async fn the_directory_vouches_for_the_dns_given_policies() {
    let Setup { iam, fake, dir } = setup().await;
    let read = ["read-photos".to_owned()];
    // Any spelling is kept as the directory's, written in one form.
    let change = iam
        .change_ldap_policies(
            "UID=dillon, OU=People,dc=MIN,dc=io",
            LdapEntity::User,
            &read,
            true,
        )
        .await
        .unwrap();
    assert_eq!(change.dn, DILLON);
    let code = |result: crate::Result<_>| result.unwrap_err().code();
    let nobody = "uid=nobody,ou=people,dc=min,dc=io";
    assert_eq!(
        code(
            iam.change_ldap_policies(nobody, LdapEntity::User, &read, true)
                .await
        ),
        "NoSuchEntity"
    );
    // A user isn't a group, nor is a user outside the base DNs a user.
    assert_eq!(
        code(
            iam.change_ldap_policies(DILLON, LdapEntity::Group, &read, true)
                .await
        ),
        "InvalidInput"
    );
    let outsider = "uid=outsider,ou=others,dc=min,dc=io";
    assert_eq!(
        code(
            iam.change_ldap_policies(outsider, LdapEntity::User, &read, true)
                .await
        ),
        "InvalidInput"
    );
    assert_eq!(
        code(
            iam.change_ldap_policies("not a dn", LdapEntity::User, &read, true)
                .await
        ),
        "InvalidInput"
    );
    // A user the directory lost can still have its policies detached.
    fake.remove(DILLON);
    assert_eq!(
        code(
            iam.change_ldap_policies(DILLON, LdapEntity::User, &read, true)
                .await
        ),
        "NoSuchEntity"
    );
    let gone = iam
        .change_ldap_policies(DILLON, LdapEntity::User, &read, false)
        .await
        .unwrap();
    assert_eq!(gone.changed, ["read-photos"]);
    assert!(iam.ldap_policies(None).unwrap().is_empty());
    // A directory that can't be asked is said to be, and none at all is refused.
    drop(iam);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = closed.local_addr().unwrap().to_string();
    drop(closed);
    let kms = LocalKms::open(dir.path().join("keyring.json")).unwrap();
    let unreachable = Iam::open(&dir.path().join("system.db"), "drive-1", &kms, None)
        .await
        .unwrap()
        .with_ldap(
            super::Directory::new(super::LdapSettings {
                server: address,
                ..fake.settings()
            })
            .unwrap(),
        );
    let failed = unreachable
        .change_ldap_policies(LIZA, LdapEntity::User, &read, true)
        .await
        .unwrap_err();
    assert_eq!(
        (failed.code(), failed.status()),
        ("ServiceUnavailable", 503)
    );
    drop(unreachable);
    let plain = Iam::open(&dir.path().join("system.db"), "drive-1", &kms, None)
        .await
        .unwrap();
    assert_eq!(
        code(
            plain
                .change_ldap_policies(LIZA, LdapEntity::User, &read, true)
                .await
        ),
        "InvalidInput"
    );
}

#[tokio::test]
async fn mappings_move_with_the_iam_export() {
    let Setup {
        iam,
        fake: _fake,
        dir: _dir,
    } = setup().await;
    let both = ["read-photos".to_owned(), "home".to_owned()];
    iam.map_ldap_policies(PROJECT_B, LdapEntity::Group, &both, true)
        .unwrap();
    iam.map_ldap_policies(DILLON, LdapEntity::User, &both[1..], true)
        .unwrap();
    let export = iam.export(false);
    assert_eq!(export.ldap_policies.len(), 2);
    let other = tempfile::tempdir().unwrap();
    let kms = LocalKms::open(other.path().join("keyring.json")).unwrap();
    let target = Iam::open(&other.path().join("system.db"), "drive-2", &kms, None)
        .await
        .unwrap();
    let report = target.import(&export, true).unwrap();
    assert_eq!(report.ldap_policies, 2);
    let moved = target.ldap_policies(None).unwrap();
    assert_eq!(
        moved
            .iter()
            .map(|m| (m.entity, m.dn.as_str(), m.policies.join(",")))
            .collect::<Vec<_>>(),
        [
            (LdapEntity::User, DILLON, "home".to_owned()),
            (LdapEntity::Group, PROJECT_B, "home,read-photos".to_owned()),
        ]
    );
    // An import checks what it brings in.
    let mut bad = export.clone();
    bad.ldap_policies[0].entity = "robot".into();
    let other = tempfile::tempdir().unwrap();
    let kms = LocalKms::open(other.path().join("keyring.json")).unwrap();
    let target = Iam::open(&other.path().join("system.db"), "drive-3", &kms, None)
        .await
        .unwrap();
    assert_eq!(
        target.import(&bad, true).unwrap_err().code(),
        "InvalidInput"
    );
    let mut bad = export;
    bad.ldap_policies[0].policies = vec!["missing".into()];
    assert_eq!(
        target.import(&bad, true).unwrap_err().code(),
        "NoSuchEntity"
    );
    // A failed import leaves nothing behind.
    assert!(target.ldap_policies(None).unwrap().is_empty());
}

#[tokio::test]
async fn the_record_of_signed_in_users_is_kept_right() {
    let Setup {
        iam,
        fake,
        dir: _dir,
    } = setup().await;
    let read = ["read-photos".to_owned()];
    // Detaching what a DN doesn't have changes nothing, and maps nothing.
    let none = iam
        .map_ldap_policies(DILLON, LdapEntity::User, &read, false)
        .unwrap();
    assert!(none.changed.is_empty() && none.policies.is_empty());
    assert!(iam.ldap_policies(None).unwrap().is_empty());

    let record = |dn: &str| iam.read(|s| Ok(s.ldap_sessions.get(dn).cloned())).unwrap();
    let record_sign_in = |dn: &'static str, user: &'static str, expires_ms: i64| {
        iam.record_ldap_sign_in(&crate::ops::LdapSignIn {
            dn,
            username: user,
            groups: &[],
            expires_ms,
        })
        .unwrap()
    };
    // A shorter session after a longer one keeps the record as long as the longer.
    let far = crate::sessions::now_seconds() * 1000 + 86_400_000;
    record_sign_in(DILLON, "dillon", far);
    record_sign_in(DILLON, "dillon", far - 80_000_000);
    assert_eq!(record(DILLON).unwrap().expires_ms, far);
    // Records whose sessions have all expired are dropped, the others checked.
    record_sign_in(LIZA, "liza", 1);
    assert_eq!(
        iam.ldap_users_to_check().unwrap(),
        [(DILLON.to_owned(), "dillon".to_owned())]
    );
    assert!(record(LIZA).is_none());
    // A user who comes back is no longer gone, so going again revokes again.
    iam.update_ldap_user(DILLON, None).unwrap();
    assert!(record(DILLON).unwrap().gone);
    iam.update_ldap_user(DILLON, Some(&[])).unwrap();
    let back = record(DILLON).unwrap();
    assert!(!back.gone);
    iam.update_ldap_user(DILLON, None).unwrap();
    assert_eq!(record(DILLON).unwrap().generation, back.generation + 1);

    // A DN mapped while it was under the base DNs can be detached after it moved out.
    let outsider = "uid=outsider,ou=others,dc=min,dc=io";
    iam.map_ldap_policies(outsider, LdapEntity::User, &read, true)
        .unwrap();
    let detached = iam
        .change_ldap_policies(outsider, LdapEntity::User, &read, false)
        .await
        .unwrap();
    assert_eq!(detached.changed, ["read-photos"]);

    drop(fake);
}
