//! `MinIO`'s service accounts: keys that act as their parent, a user or the root user,
//! narrowed by their own policy, until they're disabled, expire or their parent goes.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use teifs_crypto::LocalKms;
use teifs_iam::{
    Iam, MinioError, MinioUserChange, NewServiceAccount, Owner, ServiceAccountChange, SessionKind,
};
use teifs_policy::Date;
use zeroize::Zeroizing;

const READ_ALL: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::*"}]}"#;
const ROOT: &str = "TFROOTKEY";
const HOUR_MS: i64 = 3_600_000;

async fn open(dir: &std::path::Path) -> Iam {
    let kms = LocalKms::open(dir.join("keyring.json")).unwrap();
    let root = teifs_iam::RootKey {
        access_key: ROOT.into(),
        secret: Zeroizing::new("root-secret".into()),
    };
    Iam::open(&dir.join("system.db"), "drive-1", &kms, Some(root))
        .await
        .unwrap()
}

fn code<T: std::fmt::Debug>(result: Result<T, MinioError>) -> &'static str {
    result.unwrap_err().code()
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// Whether `key` signs and may do `action` on an object.
fn may(iam: &Iam, key: &str, action: &str) -> bool {
    let Some(credential) = iam.credential(key) else {
        return false;
    };
    let identity = credential.identity;
    identity.allows(
        &identity.context(Date::now()),
        action,
        "arn:aws:s3:::photos/a",
    )
}

/// A `MinIO` user that may read and write everything.
fn add_writer(iam: &Iam, name: &str) {
    let readwrite = vec!["readwrite".to_owned()];
    iam.minio_set_user(
        name,
        MinioUserChange {
            secret: Some("secret123"),
            enabled: Some(true),
            policies: Some(&readwrite),
        },
    )
    .unwrap();
}

/// A change to the service account a test makes.
type Change<'c> = dyn Fn(&mut NewServiceAccount<'static>) + 'c;

fn read_only<'a>() -> NewServiceAccount<'a> {
    NewServiceAccount {
        policy: Some(READ_ALL),
        ..NewServiceAccount::default()
    }
}

#[tokio::test]
async fn service_accounts_act_as_their_parent_narrowed_by_their_policy() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    add_writer(&iam, "alice");

    let all = iam
        .minio_add_service_account("alice", NewServiceAccount::default())
        .unwrap();
    assert!(all.access_key.starts_with("TKIA") && all.secret.len() == 40);
    let credential = iam.credential(&all.access_key).unwrap();
    assert_eq!(credential.secret.as_str(), all.secret.as_str());
    let session = credential.identity.session().unwrap();
    assert_eq!(session.kind(), SessionKind::Service);
    assert!(session.may_manage());
    assert!(may(&iam, &all.access_key, "s3:PutObject"));

    let narrow = iam.minio_add_service_account("alice", read_only()).unwrap();
    assert!(may(&iam, &narrow.access_key, "s3:GetObject"));
    assert!(!may(&iam, &narrow.access_key, "s3:PutObject"));
    // A policy narrows; it never adds to what the parent may do.
    iam.minio_set_user(
        "alice",
        MinioUserChange {
            policies: Some(&[]),
            ..MinioUserChange::default()
        },
    )
    .unwrap();
    assert!(!may(&iam, &narrow.access_key, "s3:GetObject"));

    // The root user's: all of it, narrowed, but never root.
    let root_all = iam
        .minio_add_service_account(ROOT, NewServiceAccount::default())
        .unwrap();
    let identity = iam.credential(&root_all.access_key).unwrap().identity;
    assert!(!identity.is_root());
    assert!(may(&iam, &root_all.access_key, "s3:PutObject"));
    let root_narrow = iam.minio_add_service_account(ROOT, read_only()).unwrap();
    assert!(may(&iam, &root_narrow.access_key, "s3:GetObject"));
    assert!(!may(&iam, &root_narrow.access_key, "s3:PutObject"));

    // Who may manage whose: the parent's name, or the root user's key.
    assert_eq!(iam.minio_parent(&identity).as_deref(), Some(ROOT));
    let theirs = iam.credential(&all.access_key).unwrap().identity;
    assert_eq!(iam.minio_parent(&theirs).as_deref(), Some("alice"));
    let alice = iam.credential("alice").unwrap().identity;
    assert_eq!(iam.minio_parent(&alice).as_deref(), Some("alice"));
    let root = iam.credential(ROOT).unwrap().identity;
    assert_eq!(iam.minio_parent(&root).as_deref(), Some(ROOT));

    // A disabled service account, or one whose parent is disabled, doesn't sign.
    iam.minio_update_service_account(
        &all.access_key,
        ServiceAccountChange {
            enabled: Some(false),
            ..ServiceAccountChange::default()
        },
    )
    .unwrap();
    assert!(iam.credential(&all.access_key).is_none());
    assert!(iam.credential(&narrow.access_key).is_some());
    iam.minio_set_user_enabled("alice", false).unwrap();
    assert!(iam.credential(&narrow.access_key).is_none());
}

#[tokio::test]
async fn what_a_service_account_is_made_with_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    add_writer(&iam, "alice");
    let new = |change: &Change<'_>| {
        let mut new = NewServiceAccount::default();
        change(&mut new);
        iam.minio_add_service_account("alice", new)
    };
    let soon = now_ms() + HOUR_MS;
    let large = format!(
        r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
        vec![r#"{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-with-a-long-name/*"}"#; 60].join(",")
    );
    let large: &'static str = Box::leak(large.into_boxed_str());
    let cases: [(&str, &Change<'_>); 15] = [
        ("XMinioInvalidResource", &|n| n.name = "1backup"),
        ("XMinioInvalidResource", &|n| {
            n.name = "a23456789012345678901234567890123";
        }),
        ("XMinioInvalidResource", &|n| {
            n.description = Box::leak("d".repeat(257).into_boxed_str());
        }),
        ("XMinioAdminInvalidArgument", &|n| {
            n.expires_ms = Some(now_ms() + 60_000);
        }),
        ("XMinioAdminInvalidArgument", &|n| {
            n.expires_ms = Some(now_ms() + 400 * 24 * HOUR_MS);
        }),
        ("XMinioAdminNoSecretKey", &|n| n.access_key = Some("svc-1")),
        ("XMinioAdminNoAccessKey", &|n| n.secret = Some("secret123")),
        ("XMinioAdminInvalidAccessKey", &|n| {
            n.access_key = Some("a=b");
            n.secret = Some("secret123");
        }),
        ("XMinioAdminInvalidSecretKey", &|n| {
            n.access_key = Some("svc-1");
            n.secret = Some("short");
        }),
        ("XMinioInvalidIAMCredentials", &|n| {
            n.access_key = Some(ROOT);
            n.secret = Some("secret123");
        }),
        ("XMinioIAMActionNotAllowed", &|n| {
            n.access_key = Some("ALICE");
            n.secret = Some("secret123");
        }),
        ("XMinioMalformedIAMPolicy", &|n| n.policy = Some("{}")),
        ("XMinioIAMServiceAccountSessionPolicyTooLarge", &|n| {
            n.policy = Some(large);
        }),
        ("XMinioAdminInvalidAccessKey", &|n| {
            n.access_key = Some("TSIAAAAAAAAAAAAAAAAA");
            n.secret = Some("secret123");
        }),
        ("XMinioIAMServiceAccountNotAllowed", &|n| {
            n.access_key = Some("bob");
            n.secret = Some("secret123");
        }),
    ];
    iam.create_user("bob", None, &[], None).unwrap();
    for (expected, change) in cases {
        assert_eq!(code(new(change)), expected);
    }
    assert_eq!(
        code(iam.minio_add_service_account("nobody", NewServiceAccount::default())),
        "XMinioAdminNoSuchUser"
    );

    // Given keys, a name, a description and an expiry are kept (to the second).
    let made = new(&|n| {
        n.access_key = Some("svc-1");
        n.secret = Some("secret123");
        n.name = "backup";
        n.description = "nightly backups";
        n.expires_ms = Some(soon);
    })
    .unwrap();
    assert_eq!(made.access_key, "svc-1");
    assert_eq!(made.expires_ms, Some(soon - soon % 1000));
    let info = iam.minio_service_account("svc-1").unwrap();
    assert_eq!(
        (
            info.parent.as_str(),
            info.name.as_str(),
            info.description.as_str()
        ),
        ("alice", "backup", "nightly backups")
    );
    assert!(info.enabled && info.implied);
    assert!(
        info.policy.contains("s3:*"),
        "the parent's: {}",
        info.policy
    );
    // Taken now, by a service account or a user's key.
    for id in ["svc-1", "alice"] {
        assert_eq!(
            code(iam.minio_add_service_account(
                ROOT,
                NewServiceAccount {
                    access_key: Some(id),
                    secret: Some("secret123"),
                    ..NewServiceAccount::default()
                }
            )),
            "XMinioIAMServiceAccountNotAllowed"
        );
    }
    assert_eq!(
        code(iam.minio_set_user(
            "svc-1",
            MinioUserChange {
                secret: Some("secret123"),
                ..MinioUserChange::default()
            }
        )),
        "XMinioAdminInvalidAccessKey"
    );
    // An expiry of 0 is never.
    let never = new(&|n| n.expires_ms = Some(0)).unwrap();
    assert_eq!(never.expires_ms, None);
}

#[tokio::test]
async fn service_accounts_change_list_and_go_with_their_parent() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    add_writer(&iam, "alice");
    let first = iam.minio_add_service_account("alice", read_only()).unwrap();
    let second = iam
        .minio_add_service_account("alice", NewServiceAccount::default())
        .unwrap();
    iam.minio_add_service_account(ROOT, NewServiceAccount::default())
        .unwrap();
    let listed: Vec<String> = iam
        .minio_service_accounts("alice")
        .into_iter()
        .map(|a| a.access_key)
        .collect();
    let mut expected = vec![first.access_key.clone(), second.access_key.clone()];
    expected.sort();
    let mut sorted = listed.clone();
    sorted.sort();
    assert_eq!(sorted, expected);
    assert_eq!(iam.minio_service_accounts(ROOT).len(), 1);
    assert!(iam.minio_service_accounts("nobody").is_empty());

    // Every part changes; an absent part stays.
    let expires = now_ms() + 2 * HOUR_MS;
    iam.minio_update_service_account(
        &first.access_key,
        ServiceAccountChange {
            secret: Some("changed123"),
            policy: Some(None),
            name: Some("renamed"),
            description: Some("about"),
            expires_ms: Some(Some(expires)),
            ..ServiceAccountChange::default()
        },
    )
    .unwrap();
    let info = iam.minio_service_account(&first.access_key).unwrap();
    assert!(info.implied && info.name == "renamed" && info.description == "about");
    assert_eq!(info.expires_ms, Some(expires - expires % 1000));
    assert!(may(&iam, &first.access_key, "s3:PutObject"));
    iam.minio_update_service_account(
        &first.access_key,
        ServiceAccountChange {
            policy: Some(Some(READ_ALL)),
            expires_ms: Some(None),
            ..ServiceAccountChange::default()
        },
    )
    .unwrap();
    let info = iam.minio_service_account(&first.access_key).unwrap();
    assert!(!info.implied && info.policy == READ_ALL && info.name == "renamed");
    assert_eq!(info.expires_ms, None);
    for (change, expected) in [
        (
            ServiceAccountChange {
                secret: Some("short"),
                ..ServiceAccountChange::default()
            },
            "XMinioAdminInvalidSecretKey",
        ),
        (
            ServiceAccountChange {
                name: Some("9lives"),
                ..ServiceAccountChange::default()
            },
            "XMinioInvalidResource",
        ),
        (
            ServiceAccountChange {
                expires_ms: Some(Some(1)),
                ..ServiceAccountChange::default()
            },
            "XMinioAdminInvalidArgument",
        ),
    ] {
        assert_eq!(
            code(iam.minio_update_service_account(&first.access_key, change)),
            expected
        );
    }
    assert_eq!(
        code(iam.minio_update_service_account("nobody", ServiceAccountChange::default())),
        "XMinioInvalidIAMCredentials"
    );

    // All of it survives a restart.
    drop(iam);
    let iam = open(dir.path()).await;
    let credential = iam.credential(&first.access_key).unwrap();
    assert_eq!(credential.secret.as_str(), "changed123");
    assert!(may(&iam, &first.access_key, "s3:GetObject"));
    assert!(!may(&iam, &first.access_key, "s3:PutObject"));

    iam.minio_remove_service_account(&second.access_key)
        .unwrap();
    assert!(iam.credential(&second.access_key).is_none());
    assert_eq!(
        code(iam.minio_remove_service_account(&second.access_key)),
        "XMinioInvalidIAMCredentials"
    );
    assert_eq!(
        code(iam.minio_service_account(&second.access_key)),
        "XMinioInvalidIAMCredentials"
    );
}

#[tokio::test]
async fn service_accounts_go_with_their_parent() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    add_writer(&iam, "alice");
    add_writer(&iam, "bob");
    let first = iam.minio_add_service_account("alice", read_only()).unwrap();
    let theirs = iam
        .minio_add_service_account(ROOT, NewServiceAccount::default())
        .unwrap();
    let bobs = iam.minio_add_service_account("bob", read_only()).unwrap();
    // IAM's DeleteUser refuses while it has some; MinIO's remove-user takes them.
    iam.minio_set_user(
        "alice",
        MinioUserChange {
            policies: Some(&[]),
            ..MinioUserChange::default()
        },
    )
    .unwrap();
    iam.delete_access_key("alice", "alice").unwrap();
    let refused = iam.delete_user("alice").unwrap_err();
    assert_eq!(refused.code(), "DeleteConflict");
    assert!(
        refused.to_string().contains("service accounts"),
        "{refused}"
    );
    iam.minio_remove_user("alice").unwrap();
    assert!(iam.credential(&first.access_key).is_none());
    assert!(iam.minio_service_accounts("alice").is_empty());
    assert!(iam.minio_service_account(&theirs.access_key).is_ok());
    assert!(may(&iam, &bobs.access_key, "s3:GetObject"));
}

#[tokio::test]
async fn an_implied_policy_leaves_out_disabled_groups() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    add_writer(&iam, "alice");
    iam.minio_update_group("devs", &["alice".to_owned()], false, None)
        .unwrap();
    iam.minio_associate(Owner::Group("devs"), &["diagnostics".to_owned()], true)
        .unwrap();
    let made = iam
        .minio_add_service_account("alice", NewServiceAccount::default())
        .unwrap();
    let policy = |iam: &Iam| iam.minio_service_account(&made.access_key).unwrap().policy;
    assert!(
        policy(&iam).contains("admin:ServerTrace"),
        "{}",
        policy(&iam)
    );
    iam.minio_set_group_enabled("devs", false).unwrap();
    assert!(
        !policy(&iam).contains("admin:ServerTrace"),
        "{}",
        policy(&iam)
    );
    assert!(policy(&iam).contains("s3:*"));
}

#[tokio::test]
async fn service_accounts_export_and_import() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    add_writer(&iam, "alice");
    let soon = now_ms() + HOUR_MS;
    let narrow = iam
        .minio_add_service_account(
            "alice",
            NewServiceAccount {
                name: "reader",
                expires_ms: Some(soon),
                ..read_only()
            },
        )
        .unwrap();
    let root = iam
        .minio_add_service_account(ROOT, NewServiceAccount::default())
        .unwrap();

    let without = iam.export(false);
    assert_eq!(without.service_accounts.len(), 2);
    assert!(without.service_accounts.iter().all(|a| a.secret.is_none()));
    assert!(!format!("{without:?}").contains(narrow.secret.as_str()));
    let other = tempfile::tempdir().unwrap();
    let to = open(other.path()).await;
    let report = to.import(&without, false).unwrap();
    assert_eq!(report.service_accounts, 0);
    assert_eq!(report.keys_without_secrets.len(), 3, "alice's key and both");

    let mut export = iam.export(true);
    let other = tempfile::tempdir().unwrap();
    let to = open(other.path()).await;
    let report = to.import(&export, false).unwrap();
    assert_eq!(report.service_accounts, 2);
    let info = to.minio_service_account(&narrow.access_key).unwrap();
    assert_eq!(
        (info.parent.as_str(), info.name.as_str()),
        ("alice", "reader")
    );
    assert_eq!(info.expires_ms, Some(soon - soon % 1000));
    assert_eq!(
        to.credential(&narrow.access_key).unwrap().secret.as_str(),
        narrow.secret.as_str()
    );
    assert!(may(&to, &narrow.access_key, "s3:GetObject"));
    assert!(!may(&to, &narrow.access_key, "s3:PutObject"));
    assert_eq!(
        to.minio_service_account(&root.access_key).unwrap().parent,
        ROOT
    );

    // One that has expired imports, but doesn't sign; a taken key doesn't import.
    let other = tempfile::tempdir().unwrap();
    let to = open(other.path()).await;
    export.service_accounts[0].expires_ms = Some(1000);
    to.import(&export, false).unwrap();
    let expired = &export.service_accounts[0].id;
    assert!(to.minio_service_account(expired).is_ok());
    assert!(to.credential(expired).is_none());
    let other = tempfile::tempdir().unwrap();
    let to = open(other.path()).await;
    export.service_accounts[0].id = "alice".into();
    assert_eq!(
        to.import(&export, false).unwrap_err().code(),
        "EntityAlreadyExists"
    );
    assert!(to.minio_users().is_empty(), "all or nothing");

    // Nor does one made later than now.
    let mut export = iam.export(true);
    export.service_accounts[0].created_ms = now_ms() + HOUR_MS;
    let other = tempfile::tempdir().unwrap();
    let to = open(other.path()).await;
    let refused = to.import(&export, false).unwrap_err();
    assert_eq!(refused.code(), "InvalidInput");
    assert!(refused.to_string().contains("impossible time"), "{refused}");
}
