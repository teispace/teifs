//! IAM against AWS's rules: entities, conflicts, quotas, persistence, sealing, and the
//! identities requests are evaluated with.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{path::Path, sync::Arc};

use teifs_crypto::LocalKms;
use teifs_iam::{Iam, IamError, Owner, RootKey};
use teifs_policy::{Context, Date, Decision, Policies, Request, evaluate};
use zeroize::Zeroizing;

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}"#;
const HOME: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*",
  "Resource":"arn:aws:s3:::home/${aws:username}/*"}]}"#;
const DENY_DELETE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
  "Action":"s3:DeleteObject","Resource":"*"}]}"#;
const ALLOW_ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

struct Drive {
    dir: tempfile::TempDir,
}

impl Drive {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn db(&self) -> std::path::PathBuf {
        self.dir.path().join("system.db")
    }

    fn keyring(&self) -> std::path::PathBuf {
        self.dir.path().join("keyring.json")
    }

    async fn open(&self) -> Iam {
        self.open_with(&self.keyring()).await.unwrap()
    }

    async fn open_with(&self, keyring: &Path) -> teifs_iam::Result<Iam> {
        let kms = LocalKms::open(keyring).unwrap();
        let root = RootKey {
            access_key: "TFROOTKEY".into(),
            secret: Zeroizing::new("root-secret".into()),
        };
        Iam::open(&self.db(), "drive-1", &kms, Some(root)).await
    }
}

fn code<T: std::fmt::Debug>(result: teifs_iam::Result<T>) -> &'static str {
    result.unwrap_err().code()
}

fn decide(iam: &Iam, access_key: &str, action: &str, resource: &str) -> Decision {
    let identity = iam.credential(access_key).unwrap().identity;
    let context = Context::new(identity.principal().clone(), Date::now());
    let policies: Vec<_> = identity.policies().iter().map(Arc::as_ref).collect();
    evaluate(
        &Policies {
            identity: &policies,
            boundary: identity.boundary(),
            ..Policies::default()
        },
        &Request {
            action,
            resource,
            context: &context,
        },
    )
}

#[tokio::test]
async fn state_and_secrets_survive_a_restart_sealed() {
    let drive = Drive::new();
    let iam = drive.open().await;
    let account = iam.account();
    assert_eq!(account.len(), 12);
    iam.create_user("alice", Some("/eng/"), &[("team".into(), "a".into())], None)
        .unwrap();
    let key = iam.create_access_key("alice").unwrap();
    assert_eq!(key.secret.len(), 40);
    iam.create_group("readers", None).unwrap();
    iam.add_user_to_group("readers", "alice").unwrap();
    let policy = iam
        .create_policy("read", None, Some("photos"), READ_PHOTOS, &[])
        .unwrap();
    iam.attach(Owner::Group("readers"), &policy.arn).unwrap();
    iam.put_inline(Owner::User("alice"), "home", HOME).unwrap();
    let before = (
        iam.users(None).unwrap(),
        iam.groups(None).unwrap(),
        iam.policies(None, false).unwrap(),
        iam.access_keys("alice").unwrap(),
    );
    drop(iam);

    let bytes = std::fs::read(drive.db()).unwrap();
    let wal = std::fs::read(drive.db().with_extension("db-wal")).unwrap_or_default();
    for haystack in [&bytes, &wal] {
        assert!(
            !haystack
                .windows(key.secret.len())
                .any(|w| w == key.secret.as_bytes()),
            "the secret is never stored in the clear"
        );
    }

    let iam = drive.open().await;
    assert_eq!(iam.account(), account);
    let after = (
        iam.users(None).unwrap(),
        iam.groups(None).unwrap(),
        iam.policies(None, false).unwrap(),
        iam.access_keys("alice").unwrap(),
    );
    assert_eq!(before, after);
    let credential = iam.credential(&key.info.id).unwrap();
    assert_eq!(credential.secret.as_str(), key.secret.as_str());
    assert_eq!(
        decide(
            &iam,
            &key.info.id,
            "s3:GetObject",
            "arn:aws:s3:::photos/a.jpg"
        ),
        Decision::Allow
    );
}

#[tokio::test]
async fn another_keyring_cant_open_the_secrets() {
    let drive = Drive::new();
    drive
        .open()
        .await
        .create_user("alice", None, &[], None)
        .unwrap();
    let other = drive.dir.path().join("other.json");
    assert_eq!(code(drive.open_with(&other).await), "ServiceFailure");
}

#[tokio::test]
async fn users_follow_aws_naming_and_conflict_rules() {
    let iam = Drive::new().open().await;
    let alice = iam.create_user("Alice", None, &[], None).unwrap();
    assert!(alice.id.starts_with("AIDA"));
    assert_eq!(
        alice.arn,
        format!("arn:aws:iam::{}:user/Alice", iam.account())
    );
    assert_eq!(
        code(iam.create_user("alice", None, &[], None)),
        "EntityAlreadyExists"
    );
    assert_eq!(
        iam.user("ALICE").unwrap().name,
        "Alice",
        "names compare without case"
    );
    for bad in ["", "a b", "a/b", &"x".repeat(65)] {
        assert_eq!(
            code(iam.create_user(bad, None, &[], None)),
            "InvalidInput",
            "{bad:?}"
        );
    }
    assert_eq!(
        code(iam.create_user("bob", Some("eng"), &[], None)),
        "InvalidInput"
    );
    iam.create_user("bob", Some("/eng/web/"), &[], None)
        .unwrap();
    iam.create_user("carol", Some("/eng/"), &[], None).unwrap();
    let names = |prefix| -> Vec<String> {
        iam.users(prefix)
            .unwrap()
            .into_iter()
            .map(|u| u.name)
            .collect()
    };
    assert_eq!(names(None), ["Alice", "bob", "carol"]);
    assert_eq!(names(Some("/eng/")), ["bob", "carol"]);
    assert_eq!(names(Some("/eng/web")), ["bob"]);

    assert_eq!(
        code(iam.update_user("bob", Some("CAROL"), None)),
        "EntityAlreadyExists"
    );
    iam.update_user("bob", Some("robert"), Some("/ops/"))
        .unwrap();
    let robert = iam.user("robert").unwrap();
    assert_eq!(robert.path, "/ops/");
    assert_eq!(code(iam.user("bob")), "NoSuchEntity");
    // Renaming keeps what hangs off the user.
    let key = iam.create_access_key("robert").unwrap();
    iam.update_user("robert", Some("bob"), None).unwrap();
    assert_eq!(iam.access_keys("bob").unwrap()[0].id, key.info.id);
    let principal = iam.credential(&key.info.id).unwrap().identity;
    assert_eq!(
        principal.principal().arn(),
        Some(format!("arn:aws:iam::{}:user/ops/bob", iam.account()).as_str())
    );
}

#[tokio::test]
async fn deleting_a_user_needs_its_dependents_gone_first() {
    let iam = Drive::new().open().await;
    iam.create_user("alice", None, &[], None).unwrap();
    iam.create_group("g", None).unwrap();
    let policy = iam
        .create_policy("p", None, None, READ_PHOTOS, &[])
        .unwrap();
    let key = iam.create_access_key("alice").unwrap();
    iam.put_inline(Owner::User("alice"), "home", HOME).unwrap();
    iam.attach(Owner::User("alice"), &policy.arn).unwrap();
    iam.add_user_to_group("g", "alice").unwrap();

    assert_eq!(code(iam.delete_user("alice")), "DeleteConflict");
    iam.delete_access_key("alice", &key.info.id).unwrap();
    assert_eq!(code(iam.delete_user("alice")), "DeleteConflict");
    iam.delete_inline(Owner::User("alice"), "home").unwrap();
    assert_eq!(code(iam.delete_user("alice")), "DeleteConflict");
    iam.detach(Owner::User("alice"), &policy.arn).unwrap();
    assert_eq!(code(iam.delete_user("alice")), "DeleteConflict");
    iam.remove_user_from_group("g", "alice").unwrap();
    iam.delete_user("alice").unwrap();
    assert_eq!(code(iam.user("alice")), "NoSuchEntity");
    assert_eq!(code(iam.delete_user("alice")), "NoSuchEntity");
}

#[tokio::test]
async fn access_keys_authenticate_until_deactivated_or_deleted() {
    let iam = Drive::new().open().await;
    let root = iam.credential("TFROOTKEY").unwrap();
    assert!(root.identity.is_root());
    assert_eq!(root.secret.as_str(), "root-secret");
    assert!(iam.credential("TKIANOPE").is_none());

    iam.create_user("alice", None, &[], None).unwrap();
    iam.create_user("bob", None, &[], None).unwrap();
    let first = iam.create_access_key("alice").unwrap();
    let second = iam.create_access_key("alice").unwrap();
    assert!(first.info.id.starts_with("TKIA") && first.info.id.len() == 20);
    assert_ne!(first.info.id, second.info.id);
    assert_eq!(code(iam.create_access_key("alice")), "LimitExceeded");
    assert!(!format!("{first:?}").contains(first.secret.as_str()));

    let credential = iam.credential(&first.info.id).unwrap();
    assert_eq!(credential.secret.as_str(), first.secret.as_str());
    assert!(!credential.identity.is_root());
    assert!(!format!("{credential:?}").contains(first.secret.as_str()));

    // Another user's name doesn't reach alice's key.
    assert_eq!(
        code(iam.update_access_key("bob", &first.info.id, false)),
        "NoSuchEntity"
    );
    assert_eq!(
        code(iam.delete_access_key("bob", &first.info.id)),
        "NoSuchEntity"
    );

    iam.update_access_key("alice", &first.info.id, false)
        .unwrap();
    assert!(
        iam.credential(&first.info.id).is_none(),
        "inactive keys don't authenticate"
    );
    assert!(
        !iam.access_keys("alice")
            .unwrap()
            .iter()
            .find(|k| k.id == first.info.id)
            .unwrap()
            .active
    );
    iam.update_access_key("alice", &first.info.id, true)
        .unwrap();
    assert!(iam.credential(&first.info.id).is_some());
    iam.delete_access_key("alice", &first.info.id).unwrap();
    assert!(iam.credential(&first.info.id).is_none());
    assert_eq!(iam.access_keys("alice").unwrap().len(), 1);
    assert_eq!(iam.access_key(&second.info.id).unwrap().user, "alice");
}

#[tokio::test]
async fn user_tags_compare_without_case() {
    let iam = Drive::new().open().await;
    let tag = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    assert_eq!(
        code(iam.create_user("a", None, &[tag("team", "x"), tag("TEAM", "y")], None)),
        "InvalidInput"
    );
    assert_eq!(
        code(iam.create_user("a", None, &[tag("aws:x", "y")], None)),
        "InvalidInput"
    );
    iam.create_user("a", None, &[tag("Department", "finance")], None)
        .unwrap();
    iam.tag_user("a", &[tag("department", "hr"), tag("site", "")])
        .unwrap();
    assert_eq!(
        iam.user("a").unwrap().tags,
        [tag("department", "hr"), tag("site", "")],
        "the new tag replaces the old one"
    );
    let many: Vec<_> = (0..49).map(|i| tag(&format!("k{i}"), "v")).collect();
    assert_eq!(code(iam.tag_user("a", &many)), "LimitExceeded");
    assert_eq!(
        iam.user("a").unwrap().tags.len(),
        2,
        "a refused change changes nothing"
    );
    iam.tag_user("a", &many[..48]).unwrap();
    iam.untag_user("a", &["DEPARTMENT".into(), "absent".into()])
        .unwrap();
    assert_eq!(iam.user("a").unwrap().tags.len(), 49);

    let key = iam.create_access_key("a").unwrap();
    let identity = iam.credential(&key.info.id).unwrap().identity;
    assert!(identity.tags().contains(&tag("site", "")));
}

#[tokio::test]
async fn policy_tags_are_case_sensitive_and_survive_a_restart() {
    let drive = Drive::new();
    let iam = drive.open().await;
    let tag = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    assert_eq!(
        code(iam.create_policy(
            "p",
            None,
            None,
            READ_PHOTOS,
            &[tag("a", "1"), tag("a", "2")]
        )),
        "InvalidInput"
    );
    let arn = iam
        .create_policy("p", None, None, READ_PHOTOS, &[tag("Team", "a")])
        .unwrap()
        .arn;
    iam.tag_policy(&arn, &[tag("team", "b"), tag("Team", "c")])
        .unwrap();
    assert_eq!(
        iam.policy(&arn).unwrap().tags,
        [tag("Team", "c"), tag("team", "b")],
        "keys differing in case are different tags"
    );
    let many: Vec<_> = (0..49).map(|i| tag(&format!("k{i:02}"), "v")).collect();
    assert_eq!(code(iam.tag_policy(&arn, &many)), "LimitExceeded");
    assert_eq!(iam.policy(&arn).unwrap().tags.len(), 2);
    iam.untag_policy(&arn, &["TEAM".into(), "team".into()])
        .unwrap();
    assert_eq!(iam.policy(&arn).unwrap().tags, [tag("Team", "c")]);
    iam.tag_policy(&arn, &many[..10]).unwrap();
    let before = iam.policy(&arn).unwrap().tags;
    drop(iam);

    let iam = drive.open().await;
    assert_eq!(
        iam.policy(&arn).unwrap().tags,
        before,
        "the same after a restart"
    );
    assert_eq!(
        code(iam.tag_policy("arn:aws:iam::000000000000:policy/none", &[])),
        "NoSuchEntity"
    );
    iam.delete_policy(&arn).unwrap();
}

#[tokio::test]
async fn groups_and_membership() {
    let iam = Drive::new().open().await;
    iam.create_user("alice", None, &[], None).unwrap();
    let group = iam.create_group("Eng", Some("/teams/")).unwrap();
    assert!(group.id.starts_with("AGPA"));
    assert_eq!(
        group.arn,
        format!("arn:aws:iam::{}:group/teams/Eng", iam.account())
    );
    assert_eq!(code(iam.create_group("eng", None)), "EntityAlreadyExists");
    iam.add_user_to_group("eng", "alice").unwrap();
    iam.add_user_to_group("eng", "alice").unwrap();
    let (info, users) = iam.group("ENG").unwrap();
    assert_eq!(info.name, "Eng");
    assert_eq!(users.len(), 1);
    assert_eq!(iam.groups_for_user("alice").unwrap()[0].name, "Eng");
    assert_eq!(code(iam.delete_group("eng")), "DeleteConflict");
    for i in 1..10 {
        iam.create_group(&format!("g{i}"), None).unwrap();
        iam.add_user_to_group(&format!("g{i}"), "alice").unwrap();
    }
    iam.create_group("g10", None).unwrap();
    assert_eq!(code(iam.add_user_to_group("g10", "alice")), "LimitExceeded");
    iam.remove_user_from_group("eng", "alice").unwrap();
    assert_eq!(
        code(iam.remove_user_from_group("eng", "alice")),
        "NoSuchEntity"
    );
    iam.update_group("eng", Some("engineering"), Some("/"))
        .unwrap();
    iam.delete_group("engineering").unwrap();
    assert_eq!(code(iam.group("engineering")), "NoSuchEntity");
}

#[tokio::test]
async fn managed_policies_keep_five_versions_numbered_for_ever() {
    let iam = Drive::new().open().await;
    let policy = iam
        .create_policy("Read", Some("/team/"), Some("reads"), READ_PHOTOS, &[])
        .unwrap();
    assert!(policy.id.starts_with("ANPA"));
    assert_eq!(
        policy.arn,
        format!("arn:aws:iam::{}:policy/team/Read", iam.account())
    );
    assert_eq!(policy.default_version, "v1");
    assert_eq!(
        code(iam.create_policy("read", None, None, READ_PHOTOS, &[])),
        "EntityAlreadyExists"
    );
    let arn = &policy.arn;
    assert_eq!(
        iam.policy(&arn.replace("Read", "READ")).unwrap().id,
        policy.id
    );
    assert_eq!(
        code(iam.policy(&arn.replace("/team/", "/"))),
        "NoSuchEntity",
        "the path is part of the ARN"
    );
    assert_eq!(
        code(iam.policy("arn:aws:iam::999999999999:policy/team/Read")),
        "NoSuchEntity"
    );
    assert_eq!(
        code(iam.policy("arn:aws:iam::aws:policy/AmazonS3FullAccess")),
        "NoSuchEntity"
    );
    assert_eq!(code(iam.policy("Read")), "InvalidInput");

    for n in 2..=5 {
        let v = iam.create_policy_version(arn, ALLOW_ALL, false).unwrap();
        assert_eq!(v.version, format!("v{n}"));
        assert!(!v.is_default);
    }
    assert_eq!(
        code(iam.create_policy_version(arn, ALLOW_ALL, false)),
        "LimitExceeded"
    );
    iam.delete_policy_version(arn, "v5").unwrap();
    let v6 = iam.create_policy_version(arn, DENY_DELETE, true).unwrap();
    assert_eq!(v6.version, "v6", "numbers aren't reused");
    assert!(v6.is_default);
    assert_eq!(iam.policy(arn).unwrap().default_version, "v6");
    assert_eq!(code(iam.delete_policy_version(arn, "v6")), "DeleteConflict");
    assert_eq!(code(iam.policy_version(arn, "v5")), "NoSuchEntity");
    assert_eq!(code(iam.policy_version(arn, "5")), "InvalidInput");
    assert_eq!(iam.policy_version(arn, "v1").unwrap().document, READ_PHOTOS);
    iam.set_default_policy_version(arn, "v1").unwrap();
    let versions: Vec<_> = iam
        .policy_versions(arn)
        .unwrap()
        .into_iter()
        .map(|v| (v.version, v.is_default))
        .collect();
    assert_eq!(
        versions,
        [
            ("v1".into(), true),
            ("v2".into(), false),
            ("v3".into(), false),
            ("v4".into(), false),
            ("v6".into(), false)
        ]
    );
    assert_eq!(
        code(iam.delete_policy(arn)),
        "DeleteConflict",
        "versions left"
    );
    for v in ["v2", "v3", "v4", "v6"] {
        iam.delete_policy_version(arn, v).unwrap();
    }
    iam.create_user("alice", None, &[], None).unwrap();
    iam.attach(Owner::User("alice"), arn).unwrap();
    assert_eq!(iam.policy(arn).unwrap().attachment_count, 1);
    assert_eq!(code(iam.delete_policy(arn)), "DeleteConflict", "attached");
    iam.detach(Owner::User("alice"), arn).unwrap();
    assert_eq!(code(iam.detach(Owner::User("alice"), arn)), "NoSuchEntity");
    iam.set_user_boundary("alice", Some(arn)).unwrap();
    assert_eq!(
        iam.user("alice").unwrap().boundary.as_deref(),
        Some(arn.as_str())
    );
    assert_eq!(code(iam.delete_policy(arn)), "DeleteConflict", "a boundary");
    iam.set_user_boundary("alice", None).unwrap();
    assert_eq!(code(iam.set_user_boundary("alice", None)), "NoSuchEntity");
    iam.delete_policy(arn).unwrap();
    assert!(iam.policies(None, false).unwrap().is_empty());
}

#[tokio::test]
async fn documents_are_checked_and_sized_as_iam_does() {
    let iam = Drive::new().open().await;
    iam.create_user("alice", None, &[], None).unwrap();
    iam.create_group("g", None).unwrap();
    for bad in [
        "",
        "{}",
        "not json",
        r#"{"Statement":[]}"#,
        "{\"a\":\"\u{100}\"}",
    ] {
        assert_eq!(
            code(iam.create_policy("p", None, None, bad, &[])),
            "MalformedPolicyDocument",
            "{bad:?}"
        );
    }
    // Identity policies name no principal.
    let with_principal = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}]}"#;
    assert_eq!(
        code(iam.put_inline(Owner::User("alice"), "p", with_principal)),
        "MalformedPolicyDocument"
    );

    // Sizes count characters other than white space.
    let sized = |n: usize| {
        let base = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::"#;
        let tail = r#""}]}"#;
        let pad = n - base.len() - tail.len();
        format!("{base}{}{tail}", "x".repeat(pad))
    };
    let spaced = |n: usize| sized(n).replace(',', " ,   ");
    iam.create_policy("max", None, None, &spaced(6144), &[])
        .unwrap();
    assert_eq!(
        code(iam.create_policy("over", None, None, &sized(6145), &[])),
        "LimitExceeded"
    );

    iam.put_inline(Owner::User("alice"), "a", &sized(1500))
        .unwrap();
    assert_eq!(
        code(iam.put_inline(Owner::User("alice"), "b", &sized(600))),
        "LimitExceeded"
    );
    // Replacing a policy doesn't count its old version.
    iam.put_inline(Owner::User("alice"), "a", &sized(2000))
        .unwrap();
    iam.put_inline(Owner::Group("g"), "a", &sized(5000))
        .unwrap();
    assert_eq!(
        code(iam.put_inline(Owner::Group("g"), "b", &sized(200))),
        "LimitExceeded"
    );
    assert_eq!(
        code(iam.put_inline(Owner::User("alice"), "bad name", HOME)),
        "InvalidInput"
    );

    assert_eq!(iam.inline_names(Owner::User("alice")).unwrap(), ["a"]);
    assert_eq!(iam.inline(Owner::User("alice"), "a").unwrap(), sized(2000));
    assert_eq!(code(iam.inline(Owner::Group("g"), "b")), "NoSuchEntity");
    assert_eq!(
        code(iam.delete_inline(Owner::Group("g"), "b")),
        "NoSuchEntity"
    );
}

#[tokio::test]
async fn attachments_are_limited_and_listed() {
    let iam = Drive::new().open().await;
    iam.create_group("g", None).unwrap();
    iam.create_user("alice", None, &[], None).unwrap();
    let arns: Vec<String> = (0..11)
        .map(|i| {
            iam.create_policy(&format!("p{i:02}"), None, None, READ_PHOTOS, &[])
                .unwrap()
                .arn
        })
        .collect();
    for arn in &arns[..10] {
        iam.attach(Owner::Group("g"), arn).unwrap();
    }
    iam.attach(Owner::Group("g"), &arns[0]).unwrap();
    assert_eq!(
        code(iam.attach(Owner::Group("g"), &arns[10])),
        "LimitExceeded"
    );
    iam.attach(Owner::User("alice"), &arns[0]).unwrap();
    let attached = iam.attached(Owner::Group("g"), None).unwrap();
    assert_eq!(attached.len(), 10);
    assert_eq!(attached[0].name, "p00");
    let (groups, users) = iam.entities_for_policy(&arns[0]).unwrap();
    assert_eq!((groups.len(), users.len()), (1, 1));
    assert_eq!(iam.policies(None, true).unwrap().len(), 10);
    assert_eq!(iam.policies(None, false).unwrap().len(), 11);
}

#[tokio::test]
async fn identities_combine_user_group_and_boundary_policies() {
    let iam = Drive::new().open().await;
    iam.create_user("alice", None, &[], None).unwrap();
    iam.create_group("readers", None).unwrap();
    iam.add_user_to_group("readers", "alice").unwrap();
    let read = iam
        .create_policy("read", None, None, READ_PHOTOS, &[])
        .unwrap();
    iam.attach(Owner::Group("readers"), &read.arn).unwrap();
    iam.put_inline(Owner::User("alice"), "home", HOME).unwrap();
    let key = iam.create_access_key("alice").unwrap().info.id;

    let allowed = |action, resource| decide(&iam, &key, action, resource);
    assert_eq!(
        allowed("s3:GetObject", "arn:aws:s3:::photos/x"),
        Decision::Allow
    );
    assert_eq!(
        allowed("s3:PutObject", "arn:aws:s3:::photos/x"),
        Decision::ImplicitDeny
    );
    assert_eq!(
        allowed("s3:PutObject", "arn:aws:s3:::home/alice/x"),
        Decision::Allow
    );
    assert_eq!(
        allowed("s3:PutObject", "arn:aws:s3:::home/bob/x"),
        Decision::ImplicitDeny
    );

    // A group's Deny applies to its members, and changes apply to the next request.
    iam.put_inline(Owner::Group("readers"), "no-delete", DENY_DELETE)
        .unwrap();
    assert_eq!(
        decide(&iam, &key, "s3:DeleteObject", "arn:aws:s3:::home/alice/x"),
        Decision::ExplicitDeny
    );
    iam.remove_user_from_group("readers", "alice").unwrap();
    assert_eq!(
        decide(&iam, &key, "s3:DeleteObject", "arn:aws:s3:::home/alice/x"),
        Decision::Allow
    );
    assert_eq!(
        decide(&iam, &key, "s3:GetObject", "arn:aws:s3:::photos/x"),
        Decision::ImplicitDeny
    );

    // A boundary caps what the policies grant.
    iam.set_user_boundary("alice", Some(&read.arn)).unwrap();
    assert_eq!(
        decide(&iam, &key, "s3:PutObject", "arn:aws:s3:::home/alice/x"),
        Decision::ImplicitDeny
    );
    iam.set_user_boundary("alice", None).unwrap();

    // A new default version applies at once.
    let deny_all =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}"#;
    iam.attach(Owner::User("alice"), &read.arn).unwrap();
    iam.create_policy_version(&read.arn, deny_all, true)
        .unwrap();
    assert_eq!(
        decide(&iam, &key, "s3:PutObject", "arn:aws:s3:::home/alice/x"),
        Decision::ExplicitDeny
    );
    iam.set_default_policy_version(&read.arn, "v1").unwrap();
    assert_eq!(
        decide(&iam, &key, "s3:PutObject", "arn:aws:s3:::home/alice/x"),
        Decision::Allow
    );
}

#[tokio::test]
async fn a_change_the_database_refuses_changes_nothing() {
    let drive = Drive::new();
    let iam = drive.open().await;
    // Another writer takes the name behind IAM's back; IAM's own check passes, the
    // database's unique index refuses, and IAM's state stays as it was.
    let other = teifs_meta::System::open(&drive.db()).unwrap();
    drop(other);
    let mut other = teifs_meta::System::open(&drive.db()).unwrap();
    other
        .iam_apply(&[teifs_meta::IamWrite::PutUser(teifs_meta::UserRow {
            id: "AIDAOTHER".into(),
            name: "bob".into(),
            path: "/".into(),
            created_ms: 0,
            boundary: None,
        })])
        .unwrap();
    assert!(matches!(
        iam.create_user("BOB", None, &[], None),
        Err(IamError::Storage(_))
    ));
    assert!(iam.users(None).unwrap().is_empty());
    iam.create_user("carol", None, &[], None).unwrap();
}

#[tokio::test]
async fn concurrent_changes_are_serialized() {
    let iam = Arc::new(Drive::new().open().await);
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let iam = iam.clone();
            std::thread::spawn(move || {
                for i in 0..25 {
                    let name = format!("u{t}-{i}");
                    iam.create_user(&name, None, &[], None).unwrap();
                    iam.create_access_key(&name).unwrap();
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(iam.users(None).unwrap().len(), 200);
}

/// An IAM with something of everything: versions, tags, a boundary, groups, inline and
/// attached policies, and an active and an inactive key.
fn populate(iam: &Iam) {
    let tags = [("team".to_owned(), "a".to_owned())];
    let read = iam
        .create_policy("read", Some("/eng/"), Some("photos"), READ_PHOTOS, &tags)
        .unwrap()
        .arn;
    iam.create_policy_version(&read, ALLOW_ALL, true).unwrap();
    iam.create_policy_version(&read, HOME, false).unwrap();
    let boundary = iam
        .create_policy("boundary", None, None, ALLOW_ALL, &[])
        .unwrap()
        .arn;
    iam.create_group("devs", Some("/eng/")).unwrap();
    iam.put_inline(Owner::Group("devs"), "home", HOME).unwrap();
    iam.attach(Owner::Group("devs"), &read).unwrap();
    iam.create_user("alice", Some("/eng/"), &tags, Some(&boundary))
        .unwrap();
    iam.add_user_to_group("devs", "alice").unwrap();
    iam.put_inline(Owner::User("alice"), "no-delete", DENY_DELETE)
        .unwrap();
    iam.attach(Owner::User("alice"), &read).unwrap();
    iam.create_access_key("alice").unwrap();
    let old = iam.create_access_key("alice").unwrap();
    iam.update_access_key("alice", &old.info.id, false).unwrap();
    iam.create_user("bob", None, &[], None).unwrap();
}

#[tokio::test]
async fn an_export_imports_into_another_drive_as_it_was() {
    let (source, target) = (Drive::new(), Drive::new());
    let from = source.open().await;
    populate(&from);
    let export = from.export(true);
    assert_eq!(export.format, teifs_types::admin::IAM_FORMAT);
    let read = &export
        .policies
        .iter()
        .find(|p| p.name == "read")
        .unwrap()
        .versions;
    assert_eq!(
        read.iter().map(|v| v.is_default).collect::<Vec<_>>(),
        [false, true, false]
    );

    let to = target.open().await;
    assert_ne!(to.account(), from.account());
    let report = to.import(&export, true).unwrap();
    assert_eq!(
        (
            report.policies,
            report.groups,
            report.users,
            report.access_keys
        ),
        (2, 1, 2, 2)
    );
    assert!(report.keys_without_secrets.is_empty());
    assert_eq!(report.account, from.account());
    // Everything is as it was, and stays so when the drive opens again.
    assert_eq!(to.export(true), export);
    drop(to);
    let to = target.open().await;
    assert_eq!(to.export(true), export);
    // The keys sign as before: the active one for alice, with the same secret.
    for key in &export.users[0].access_keys {
        let credential = to.credential(&key.id);
        if key.active {
            let credential = credential.unwrap();
            assert_eq!(Some(credential.secret.as_str()), key.secret.as_deref());
            // The same user by name and ARN (unique ids are made anew, as by CreateUser).
            assert_eq!(
                credential.identity.principal().arn(),
                from.credential(&key.id).unwrap().identity.principal().arn()
            );
        } else {
            assert!(credential.is_none());
        }
    }
}

#[tokio::test]
async fn an_export_without_secrets_brings_no_keys() {
    let (source, target) = (Drive::new(), Drive::new());
    let from = source.open().await;
    populate(&from);
    let export = from.export(false);
    assert!(
        export
            .users
            .iter()
            .flat_map(|u| &u.access_keys)
            .all(|k| k.secret.is_none())
    );
    let to = target.open().await;
    let account = to.account();
    let report = to.import(&export, false).unwrap();
    assert_eq!(report.access_keys, 0);
    assert_eq!(report.keys_without_secrets.len(), 2);
    assert!(to.access_keys("alice").unwrap().is_empty());
    // Without adopting, the account keeps its id.
    assert_eq!((report.account, to.account()), (account.clone(), account));
}

#[tokio::test]
async fn an_import_is_all_or_nothing() {
    let (source, target) = (Drive::new(), Drive::new());
    let from = source.open().await;
    populate(&from);
    let good = from.export(true);
    let to = target.open().await;
    let account = to.account();
    let empty = to.export(true);
    let broken = |change: &dyn Fn(&mut teifs_types::admin::IamExport)| {
        let mut export = good.clone();
        change(&mut export);
        export
    };
    // Each fails at the very end, after everything before it was made.
    // A key for bob, valid but for what each case changes.
    let key_for_bob = |change: &dyn Fn(&mut teifs_types::admin::ExportedKey)| {
        broken(&|e| {
            let mut key = e.users[0].access_keys[0].clone();
            key.id = "TKIAIMPORTEDKEY00001".into();
            change(&mut key);
            e.users[1].access_keys.push(key);
        })
    };
    let cases: [(&str, teifs_types::admin::IamExport); 9] = [
        ("InvalidInput", key_for_bob(&|k| k.created_ms = i64::MAX)),
        (
            "InvalidInput",
            key_for_bob(&|k| k.secret = Some(format!("{} ", "s".repeat(39)))),
        ),
        (
            "LimitExceeded",
            broken(&|e| {
                let mut key = e.users[0].access_keys[0].clone();
                key.id = "TKIAIMPORTEDKEY00002".into();
                e.users[0].access_keys.push(key);
            }),
        ),
        (
            "NoSuchEntity",
            broken(&|e| e.users[1].attached.push("missing".into())),
        ),
        (
            "MalformedPolicyDocument",
            broken(&|e| {
                e.users[1].inline.insert("bad".into(), "{}".into());
            }),
        ),
        (
            "InvalidInput",
            broken(&|e| e.users[1].name = "no spaces allowed".into()),
        ),
        (
            "NoSuchEntity",
            broken(&|e| e.users[1].groups.push("missing".into())),
        ),
        (
            "InvalidInput",
            broken(&|e| {
                let mut key = e.users[0].access_keys[0].clone();
                key.id = "TKIASHORTSECRET0001".into();
                key.secret = Some("short".into());
                e.users[1].access_keys.push(key);
            }),
        ),
        (
            "EntityAlreadyExists",
            broken(&|e| {
                let key = e.users[0].access_keys[0].clone();
                e.users[1].access_keys.push(key);
            }),
        ),
    ];
    for (expected, export) in cases {
        assert_eq!(code(to.import(&export, true)), expected);
        assert_eq!(to.export(true), empty, "{expected}");
        assert_eq!(to.account(), account);
    }
    // Nothing was left behind in the database either.
    drop(to);
    let to = target.open().await;
    assert_eq!(to.export(true), empty);
    to.import(&good, true).unwrap();
}

#[tokio::test]
async fn an_import_is_refused_what_it_cannot_bring() {
    let drive = Drive::new();
    let iam = drive.open().await;
    let empty = iam.export(true);
    let mut export = empty.clone();
    export.format = "teifs-iam/2".into();
    assert_eq!(code(iam.import(&export, false)), "InvalidInput");
    let mut export = empty.clone();
    export.account = "12345".into();
    assert_eq!(code(iam.import(&export, true)), "InvalidInput");
    // Adopting the account alone is fine...
    export.account = "210987654321".into();
    iam.import(&export, true).unwrap();
    assert_eq!(iam.account(), "210987654321");
    // ...but only into an empty IAM.
    iam.create_user("carol", None, &[], None).unwrap();
    assert_eq!(code(iam.import(&empty, false)), "EntityAlreadyExists");
    // No key may take the root's id, and a policy needs exactly one default version.
    let other = Drive::new();
    let kms = LocalKms::open(other.keyring()).unwrap();
    let root = RootKey {
        access_key: "TFROOTKEY00000000000".into(),
        secret: Zeroizing::new("root-secret".into()),
    };
    let iam = Iam::open(&other.db(), "drive-2", &kms, Some(root))
        .await
        .unwrap();
    let source = Drive::new();
    let from = source.open().await;
    populate(&from);
    let mut export = from.export(true);
    let mut taken = export.clone();
    taken.users[0].access_keys[0].id = "TFROOTKEY00000000000".into();
    assert_eq!(code(iam.import(&taken, false)), "EntityAlreadyExists");
    let read = export
        .policies
        .iter()
        .position(|p| p.name == "read")
        .unwrap();
    export.policies[read].versions[0].is_default = true;
    assert_eq!(code(iam.import(&export, false)), "InvalidInput");
    export.policies[read].versions.clear();
    assert_eq!(code(iam.import(&export, false)), "InvalidInput");
    assert!(iam.users(None).unwrap().is_empty());
}

fn root_key(id: &str, secret: &str) -> RootKey {
    RootKey {
        access_key: id.into(),
        secret: Zeroizing::new(secret.into()),
    }
}

#[tokio::test]
async fn the_root_key_is_replaced_only_once_it_is_saved() {
    let drive = Drive::new();
    let iam = drive.open().await;
    iam.create_user("alice", None, &[], None).unwrap();
    let alice = iam.create_access_key("alice").unwrap();
    // A failed save changes nothing.
    let failed = iam.replace_root_key(root_key("TFNEWROOTKEY", "new-secret"), |_| {
        Err(std::io::Error::other("disk full"))
    });
    assert_eq!(code(failed), "ServiceFailure");
    assert!(iam.credential("TFROOTKEY").is_some());
    assert!(iam.credential("TFNEWROOTKEY").is_none());
    // A key that's taken is refused before anything is saved.
    for taken in [alice.info.id.as_str(), "TFROOTKEY"] {
        let result = iam.replace_root_key(root_key(taken, "s"), |_| panic!("saved"));
        assert_eq!(code(result), "EntityAlreadyExists", "{taken}");
    }
    let mut saved = None;
    iam.replace_root_key(root_key("TFNEWROOTKEY", "new-secret"), |key| {
        saved = Some(key.access_key.clone());
        Ok(())
    })
    .unwrap();
    assert_eq!(saved.as_deref(), Some("TFNEWROOTKEY"));
    assert!(iam.credential("TFROOTKEY").is_none());
    let root = iam.credential("TFNEWROOTKEY").unwrap();
    assert_eq!(root.secret.as_str(), "new-secret");
    assert!(root.identity.is_root());
    // Users' keys are untouched, and none may take the new root's id later.
    assert!(iam.credential(&alice.info.id).is_some());
    iam.create_user("bob", None, &[], None).unwrap();
    iam.create_access_key("bob").unwrap();
}

#[tokio::test]
async fn a_server_without_a_root_key_has_none_to_replace() {
    let drive = Drive::new();
    let kms = LocalKms::open(drive.keyring()).unwrap();
    let iam = Iam::open(&drive.db(), "drive-1", &kms, None).await.unwrap();
    let result = iam.replace_root_key(root_key("TFNEWROOTKEY", "s"), |_| Ok(()));
    assert_eq!(code(result), "InvalidInput");
    assert!(iam.credential("TFNEWROOTKEY").is_none());
}
