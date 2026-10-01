//! IAM as `MinIO`'s admin API changes it: users named by their access keys, their and
//! groups' status, canned policies by name, and who has which.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use teifs_crypto::LocalKms;
use teifs_iam::{Iam, MinioError, MinioUserChange, Owner, RootKey};
use teifs_policy::{Context, Date, Decision, Policies, Request, evaluate};
use zeroize::Zeroizing;

const READ_ALL: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::*"}]}"#;

async fn open(dir: &std::path::Path) -> Iam {
    let kms = LocalKms::open(dir.join("keyring.json")).unwrap();
    let root = RootKey {
        access_key: "TFROOTKEY".into(),
        secret: Zeroizing::new("root-secret".into()),
    };
    Iam::open(&dir.join("system.db"), "drive-1", &kms, Some(root))
        .await
        .unwrap()
}

fn code<T: std::fmt::Debug>(result: Result<T, MinioError>) -> &'static str {
    result.unwrap_err().code()
}

fn allows(iam: &Iam, key: &str, action: &str) -> bool {
    let Some(credential) = iam.credential(key) else {
        return false;
    };
    let identity = credential.identity;
    let context = Context::new(identity.principal().clone(), Date::now());
    let policies: Vec<_> = identity.policies().iter().map(AsRef::as_ref).collect();
    evaluate(
        &Policies {
            identity: &policies,
            boundary: identity.boundary(),
            ..Policies::default()
        },
        &Request {
            action,
            resource: "arn:aws:s3:::photos/a",
            context: &context,
        },
    ) == Decision::Allow
}

fn user<'a>(secret: Option<&'a str>, policies: Option<&'a [String]>) -> MinioUserChange<'a> {
    MinioUserChange {
        secret,
        enabled: Some(true),
        policies,
    }
}

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[tokio::test]
async fn users_are_named_by_their_access_keys_and_can_be_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    iam.minio_set_user("minio-user", user(Some("secret123"), None))
        .unwrap();
    assert_eq!(
        iam.credential("minio-user").unwrap().secret.as_str(),
        "secret123"
    );
    let info = iam.minio_user("minio-user").unwrap();
    assert!(info.enabled && info.policies.is_empty() && info.groups.is_empty());

    for (access_key, secret, expected) in [
        ("ab", Some("secret123"), "XMinioAdminInvalidAccessKey"),
        ("a=bc", Some("secret123"), "XMinioAdminInvalidAccessKey"),
        (
            "TSIAAAAAAAAAAAAAAAAA",
            Some("secret123"),
            "XMinioAdminInvalidAccessKey",
        ),
        (
            "TFROOTKEY",
            Some("secret123"),
            "XMinioAdminInvalidAccessKey",
        ),
        ("newcomer", None, "XMinioAdminInvalidSecretKey"),
        ("newcomer", Some("short"), "XMinioAdminInvalidSecretKey"),
        ("newcomer", Some("has space"), "XMinioAdminInvalidSecretKey"),
    ] {
        assert_eq!(
            code(iam.minio_set_user(access_key, user(secret, None))),
            expected,
            "{access_key}"
        );
    }
    assert_eq!(code(iam.minio_user("newcomer")), "XMinioAdminNoSuchUser");

    // Policies are replaced by name; an unknown one changes nothing.
    let readwrite = names(&["readwrite"]);
    iam.minio_set_user("minio-user", user(None, Some(&readwrite)))
        .unwrap();
    assert!(allows(&iam, "minio-user", "s3:PutObject"));
    let readonly = names(&["readonly"]);
    iam.minio_set_user("minio-user", user(None, Some(&readonly)))
        .unwrap();
    assert!(!allows(&iam, "minio-user", "s3:PutObject"));
    assert!(allows(&iam, "minio-user", "s3:GetObject"));
    let unknown = names(&["readwrite", "nothing"]);
    assert_eq!(
        code(iam.minio_set_user("minio-user", user(Some("changed123"), Some(&unknown)))),
        "XMinioAdminNoSuchPolicy"
    );
    assert_eq!(iam.minio_user("minio-user").unwrap().policies, ["readonly"]);
    assert_eq!(
        iam.credential("minio-user").unwrap().secret.as_str(),
        "secret123"
    );

    // Disabled, its key doesn't sign; the status survives a restart and an export.
    iam.minio_set_user_enabled("minio-user", false).unwrap();
    assert!(iam.credential("minio-user").is_none());
    drop(iam);
    let iam = open(dir.path()).await;
    assert!(!iam.minio_user("minio-user").unwrap().enabled);
    let export = iam.export(true);
    let other = tempfile::tempdir().unwrap();
    let to = open(other.path()).await;
    to.import(&export, true).unwrap();
    assert!(!to.minio_user("minio-user").unwrap().enabled);
    assert!(to.credential("minio-user").is_none());
    iam.minio_set_user(
        "minio-user",
        MinioUserChange {
            enabled: Some(true),
            ..MinioUserChange::default()
        },
    )
    .unwrap();
    assert!(allows(&iam, "minio-user", "s3:GetObject"));
    assert_eq!(
        code(iam.minio_set_user_enabled("nobody", false)),
        "XMinioAdminNoSuchUser"
    );
}

#[tokio::test]
async fn secrets_change_and_removing_a_user_takes_everything() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    iam.minio_set_user("minio-user", user(Some("secret123"), None))
        .unwrap();
    let readonly = names(&["readonly"]);
    // A new secret keeps the key; the key's own secret can be changed by it.
    let created = iam.access_key("minio-user").unwrap().created_ms;
    iam.minio_set_user("minio-user", user(Some("another123"), None))
        .unwrap();
    assert_eq!(
        iam.credential("minio-user").unwrap().secret.as_str(),
        "another123"
    );
    iam.minio_change_secret("minio-user", "mine12345").unwrap();
    assert_eq!(
        iam.credential("minio-user").unwrap().secret.as_str(),
        "mine12345"
    );
    assert_eq!(iam.access_key("minio-user").unwrap().created_ms, created);
    assert_eq!(
        code(iam.minio_change_secret("nobody", "mine12345")),
        "XMinioAdminInvalidAccessKey"
    );
    assert_eq!(
        code(iam.minio_change_secret("minio-user", "short")),
        "XMinioAdminInvalidSecretKey"
    );

    // Users made through IAM's API are MinIO's too: one gets a key of its name.
    iam.create_user("alice", None, &[], None).unwrap();
    let theirs = iam.create_access_key("alice").unwrap().info.id;
    iam.minio_set_user("alice", user(Some("alice-secret"), None))
        .unwrap();
    assert_eq!(iam.access_keys("alice").unwrap().len(), 2);
    iam.create_user("Bob", None, &[], None).unwrap();
    assert_eq!(
        code(iam.minio_set_user("bob", user(Some("bob-secret"), None))),
        "XMinioAdminInvalidAccessKey",
        "names compare without case"
    );
    assert_eq!(
        code(iam.minio_set_user(&theirs, user(Some("stolen123"), None))),
        "XMinioAdminInvalidAccessKey",
        "another user's key"
    );
    // A user renamed keeps its key, which a new user of the old name can't take.
    iam.minio_set_user("carol", user(Some("carol-secret"), None))
        .unwrap();
    iam.update_user("carol", Some("carol-old"), None).unwrap();
    iam.create_user("carol", None, &[], None).unwrap();
    assert_eq!(
        code(iam.minio_set_user("carol", user(Some("taken1234"), None))),
        "XMinioAdminInvalidAccessKey"
    );
    assert_eq!(
        iam.credential("carol").unwrap().secret.as_str(),
        "carol-secret"
    );
    assert_eq!(
        iam.minio_users()
            .iter()
            .map(|u| u.name.as_str())
            .collect::<Vec<_>>(),
        ["alice", "Bob", "carol", "carol-old", "minio-user"]
    );

    // Removing a user takes its keys, policies and memberships with it.
    iam.minio_update_group("devs", &names(&["alice"]), false, None)
        .unwrap();
    iam.put_inline(Owner::User("alice"), "inline", READ_ALL)
        .unwrap();
    iam.minio_set_user("alice", user(None, Some(&readonly)))
        .unwrap();
    iam.minio_remove_user("alice").unwrap();
    assert!(iam.credential("alice").is_none() && iam.credential(&theirs).is_none());
    assert_eq!(code(iam.minio_user("alice")), "XMinioAdminNoSuchUser");
    assert!(iam.minio_group("devs").unwrap().members.is_empty());
    assert_eq!(
        code(iam.minio_remove_user("alice")),
        "XMinioAdminNoSuchUser"
    );
}

#[tokio::test]
async fn groups_are_made_by_their_members_and_disabled_lose_their_policies() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    iam.minio_set_user("member", user(Some("secret123"), None))
        .unwrap();
    assert_eq!(
        code(iam.minio_update_group("devs", &names(&["member", "nobody"]), false, None)),
        "XMinioAdminNoSuchUser"
    );
    assert_eq!(code(iam.minio_group("devs")), "XMinioAdminNoSuchGroup");
    iam.minio_update_group("devs", &names(&["member"]), false, None)
        .unwrap();
    iam.minio_associate(Owner::Group("devs"), &names(&["readwrite"]), true)
        .unwrap();
    let group = iam.minio_group("devs").unwrap();
    assert_eq!(
        (group.enabled, group.members, group.policies),
        (true, names(&["member"]), names(&["readwrite"]))
    );
    assert!(allows(&iam, "member", "s3:PutObject"));
    assert_eq!(iam.minio_user("member").unwrap().groups, ["devs"]);

    iam.minio_update_group("devs", &[], false, Some(false))
        .unwrap();
    assert!(!allows(&iam, "member", "s3:PutObject"));
    assert!(!iam.minio_group("devs").unwrap().enabled);
    iam.minio_set_group_enabled("devs", true).unwrap();
    assert!(allows(&iam, "member", "s3:PutObject"));
    assert_eq!(
        code(iam.minio_set_group_enabled("nobody", true)),
        "XMinioAdminNoSuchGroup"
    );

    assert_eq!(
        code(iam.minio_update_group("devs", &[], true, None)),
        "XMinioAdminGroupNotEmpty"
    );
    iam.minio_update_group("devs", &names(&["member"]), true, None)
        .unwrap();
    assert!(iam.minio_group("devs").unwrap().members.is_empty());
    iam.minio_update_group("devs", &[], true, None).unwrap();
    assert_eq!(iam.minio_groups(), Vec::<String>::new());
    assert_eq!(
        code(iam.minio_update_group("devs", &[], true, None)),
        "XMinioAdminNoSuchGroup"
    );
}

#[tokio::test]
async fn canned_policies_are_put_by_name_and_override_built_in_ones() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    iam.minio_put_policy("custom", READ_ALL, false).unwrap();
    for _ in 0..6 {
        iam.minio_put_policy("custom", READ_ALL, false).unwrap();
    }
    let arn = format!("arn:aws:iam::{}:policy/custom", iam.account());
    let versions = iam.policy_versions(&arn).unwrap();
    assert_eq!(
        versions
            .iter()
            .map(|v| v.version.as_str())
            .collect::<Vec<_>>(),
        ["v3", "v4", "v5", "v6", "v7"],
        "the oldest are dropped"
    );
    assert!(versions[4].is_default);
    assert_eq!(
        code(iam.minio_put_policy("custom", "{", false)),
        "XMinioMalformedIAMPolicy"
    );

    // A built-in policy is overridden only when asked.
    assert_eq!(
        code(iam.minio_put_policy("readwrite", READ_ALL, false)),
        "XMinioAdminInvalidArgument"
    );
    iam.minio_put_policy("readwrite", READ_ALL, true).unwrap();
    assert_eq!(iam.minio_policy("readwrite").unwrap().document, READ_ALL);
    let listed = iam.minio_policies();
    assert_eq!(
        listed.len(),
        16,
        "15 built-in, one of them overridden, and custom"
    );
    assert_eq!(listed.iter().filter(|p| p.name == "readwrite").count(), 1);
    assert_eq!(code(iam.minio_policy("nothing")), "XMinioAdminNoSuchPolicy");
}

#[tokio::test]
async fn policies_are_attached_by_name_and_removed_when_unused() {
    let dir = tempfile::tempdir().unwrap();
    let iam = open(dir.path()).await;
    iam.minio_put_policy("custom", READ_ALL, false).unwrap();
    iam.minio_put_policy("readwrite", READ_ALL, true).unwrap();
    // Attaching and detaching say what changed, and refuse to change nothing.
    iam.minio_set_user("member", user(Some("secret123"), None))
        .unwrap();
    iam.minio_update_group("devs", &names(&["member"]), false, None)
        .unwrap();
    let both = names(&["custom", "consoleAdmin"]);
    assert_eq!(
        iam.minio_associate(Owner::User("member"), &both, true)
            .unwrap(),
        ["custom", "consoleAdmin"]
    );
    assert_eq!(
        code(iam.minio_associate(Owner::User("member"), &both, true)),
        "XMinioAdminPolicyChangeAlreadyApplied"
    );
    assert_eq!(
        iam.minio_associate(Owner::User("member"), &names(&["consoleAdmin"]), false)
            .unwrap(),
        ["consoleAdmin"]
    );
    iam.minio_associate(Owner::Group("devs"), &names(&["readwrite"]), true)
        .unwrap();
    for (owner, policies, expected) in [
        (
            Owner::User("nobody"),
            names(&["custom"]),
            "XMinioAdminNoSuchUser",
        ),
        (
            Owner::Group("nobody"),
            names(&["custom"]),
            "XMinioAdminNoSuchGroup",
        ),
        (
            Owner::User("member"),
            names(&["nothing"]),
            "XMinioAdminNoSuchPolicy",
        ),
        (
            Owner::User("member"),
            Vec::new(),
            "XMinioAdminInvalidArgument",
        ),
        (
            Owner::Role("member"),
            names(&["custom"]),
            "XMinioAdminInvalidArgument",
        ),
    ] {
        assert_eq!(code(iam.minio_associate(owner, &policies, true)), expected);
    }

    // Who has which.
    let all = iam.minio_policy_entities(&[], &[], &[]);
    assert_eq!(all.users.len(), 1);
    assert_eq!(all.users[0].policies, ["custom"]);
    assert_eq!(all.users[0].groups[0].policies, ["readwrite"]);
    assert_eq!(all.groups[0].group, "devs");
    assert_eq!(
        all.policies
            .iter()
            .map(|p| (p.policy.as_str(), p.users.len(), p.groups.len()))
            .collect::<Vec<_>>(),
        [("custom", 1, 0), ("readwrite", 0, 1)]
    );
    let some = iam.minio_policy_entities(&[], &[], &names(&["consoleAdmin", "nothing"]));
    assert!(some.users.is_empty() && some.groups.is_empty());
    assert_eq!(some.policies.len(), 1);
    assert!(some.policies[0].users.is_empty());

    // Only an unused policy of the account's own is removed.
    assert_eq!(
        code(iam.minio_remove_policy("custom")),
        "XMinioIAMPolicyInUse"
    );
    assert_eq!(
        code(iam.minio_remove_policy("readwrite")),
        "XMinioIAMPolicyInUse"
    );
    assert_eq!(
        code(iam.minio_remove_policy("consoleAdmin")),
        "XMinioAdminInvalidArgument"
    );
    assert_eq!(
        code(iam.minio_remove_policy("nothing")),
        "XMinioAdminNoSuchPolicy"
    );
    iam.minio_associate(Owner::User("member"), &names(&["custom"]), false)
        .unwrap();
    iam.minio_remove_policy("custom").unwrap();
    assert_eq!(code(iam.minio_policy("custom")), "XMinioAdminNoSuchPolicy");
}
