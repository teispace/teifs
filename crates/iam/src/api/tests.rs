#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{collections::BTreeSet, sync::Arc};

use teifs_crypto::LocalKms;
use teifs_policy::{Context, Date, IamKey};
use zeroize::Zeroizing;

use super::{ACTIONS, On};
use crate::{Call, Iam, Identity, Owner, Reply, RootKey};

const REFERENCE: &str = include_str!("../../tests/fixtures/iam-reference.json");
/// A policy that allows nothing in IAM.
const NOTHING: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}]}"#;
const ALLOW_ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

fn strings(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn actions_match_aws_service_reference() {
    let reference: serde_json::Value = serde_json::from_str(REFERENCE).unwrap();
    let names: BTreeSet<&str> = ACTIONS.iter().map(|a| a.name).collect();
    assert_eq!(names.len(), ACTIONS.len(), "an action is listed twice");
    for action in ACTIONS {
        let entry = &reference["actions"][action.name];
        assert!(entry.is_object(), "{} isn't an IAM action", action.name);
        let on = match action.on {
            On::Any => None,
            On::User => Some("user"),
            On::Group => Some("group"),
            On::Policy => Some("policy"),
        };
        assert_eq!(
            strings(&entry["resources"]),
            on.into_iter().map(str::to_owned).collect(),
            "{}'s resource",
            action.name
        );
        assert_eq!(
            strings(&entry["conditionKeys"]),
            action.keys.iter().map(|k| (*k).to_owned()).collect(),
            "{}'s condition keys",
            action.name
        );
        // What else the operation needs (`CreateUser` with tags needs `TagUser`) is an
        // action the API checks too.
        for needed in strings(&reference["operations"][action.name]) {
            assert!(
                names.contains(needed.as_str()),
                "{} needs {needed}",
                action.name
            );
        }
    }
    // The resources' own keys, which every action on them sets.
    let resource_keys = |kind: &str| strings(&reference["resources"][kind]["conditionKeys"]);
    assert_eq!(
        resource_keys("user"),
        ["aws:ResourceTag/${TagKey}", "iam:ResourceTag/${TagKey}"]
            .map(str::to_owned)
            .into()
    );
    assert_eq!(
        resource_keys("policy"),
        ["aws:ResourceTag/${TagKey}".to_owned()].into()
    );
    assert!(resource_keys("group").is_empty());
    // Every `iam:` key AWS defines is one policies can name.
    let ours: BTreeSet<String> = IamKey::ALL
        .iter()
        .map(|k| k.name().to_owned())
        .chain(["iam:ResourceTag/${TagKey}".to_owned()])
        .collect();
    let theirs: BTreeSet<String> = strings(&reference["conditionKeys"])
        .into_iter()
        .filter(|k| k.starts_with("iam:"))
        .collect();
    assert_eq!(ours, theirs);
    assert!(strings(&reference["sts"]["actions"]["GetCallerIdentity"]["resources"]).is_empty());
}

struct Drive {
    _dir: tempfile::TempDir,
    iam: Iam,
    account: String,
}

const ROOT: &str = "TFROOTKEY";

async fn drive() -> Drive {
    let dir = tempfile::tempdir().unwrap();
    let kms = LocalKms::open(dir.path().join("keyring.json")).unwrap();
    let root = RootKey {
        access_key: ROOT.into(),
        secret: Zeroizing::new("root-secret".into()),
    };
    let iam = Iam::open(&dir.path().join("system.db"), "d", &kms, Some(root))
        .await
        .unwrap();
    let account = iam.account();
    Drive {
        _dir: dir,
        iam,
        account,
    }
}

impl Drive {
    fn identity(&self, key: &str) -> Arc<Identity> {
        self.iam.credential(key).unwrap().identity
    }

    fn root(&self) -> Arc<Identity> {
        self.identity(ROOT)
    }

    /// A user with `policy` inline; its access key.
    fn user(&self, name: &str, policy: &str) -> String {
        self.iam.create_user(name, None, &[], None).unwrap();
        self.iam.put_inline(Owner::User(name), "p", policy).unwrap();
        self.iam.create_access_key(name).unwrap().info.id
    }

    fn call(&self, identity: &Identity, body: &str) -> Reply {
        let context = Context::new(identity.principal().clone(), Date::now());
        self.iam.serve_iam(&Call {
            identity,
            context: &context,
            body: body.as_bytes(),
            request_id: "req-1",
        })
    }

    fn ok(&self, identity: &Identity, body: &str) -> String {
        let reply = self.call(identity, body);
        assert_eq!(reply.status, 200, "{body}: {}", reply.body);
        reply.body
    }

    fn code(&self, identity: &Identity, body: &str) -> String {
        let reply = self.call(identity, body);
        assert_ne!(reply.status, 200, "{body} succeeded");
        between(&reply.body, "<Code>", "</Code>").to_owned()
    }

    fn policy_arn(&self, name: &str) -> String {
        format!("arn:aws:iam::{}:policy/{name}", self.account)
    }
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text
        .find(start)
        .unwrap_or_else(|| panic!("no {start} in {text}"))
        + start.len();
    let to = text[from..].find(end).unwrap() + from;
    &text[from..to]
}

fn statement(effect: &str, action: &str, resource: &str, condition: &str) -> String {
    let condition = if condition.is_empty() {
        String::new()
    } else {
        format!(r#","Condition":{condition}"#)
    };
    format!(r#"{{"Effect":"{effect}","Action":"{action}","Resource":"{resource}"{condition}}}"#)
}

fn policy(statements: &[String]) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
        statements.join(",")
    )
}

fn enc(text: &str) -> String {
    form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

#[tokio::test]
async fn answers_are_shaped_as_aws_answers() {
    let d = drive().await;
    let root = d.root();
    let body = d.ok(
        &root,
        "Action=CreateUser&Version=2010-05-08&UserName=Alice&Path=%2Fteam%2F\
         &Tags.member.1.Key=dept&Tags.member.1.Value=R+D",
    );
    assert!(
        body.starts_with(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CreateUserResponse \
             xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><CreateUserResult><User>\
             <Path>/team/</Path><UserName>Alice</UserName><UserId>AIDA"
        ),
        "{body}"
    );
    assert!(body.contains(&format!(
        "<Arn>arn:aws:iam::{}:user/team/Alice</Arn>",
        d.account
    )));
    assert!(body.contains("<Tags><member><Key>dept</Key><Value>R D</Value></member></Tags>"));
    assert!(body.ends_with(
        "</CreateUserResult><ResponseMetadata><RequestId>req-1</RequestId>\
         </ResponseMetadata></CreateUserResponse>"
    ));

    // No result element for actions without one.
    let body = d.ok(&root, "Action=DeleteUser&UserName=alice");
    assert!(body.contains("<DeleteUserResponse xmlns"));
    assert!(!body.contains("DeleteUserResult"));

    let reply = d.call(&root, "Action=GetUser&UserName=nobody");
    assert_eq!(reply.status, 404);
    assert_eq!(
        reply.body,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ErrorResponse \
         xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Type>Sender</Type>\
         <Code>NoSuchEntity</Code><Message>The user with name nobody cannot be found.\
         </Message></Error><RequestId>req-1</RequestId></ErrorResponse>"
    );

    for (body, code) in [
        ("UserName=a", "MissingAction"),
        ("Action=CreateRole", "InvalidAction"),
        ("Action=ListUsers&Version=2011-06-15", "InvalidAction"),
        ("Action=CreateUser", "ValidationError"),
        ("Action=CreateUser&UserName=a&UserName=b", "ValidationError"),
        ("Action=ListUsers&MaxItems=0", "ValidationError"),
        (
            "Action=UpdateAccessKey&UserName=a&AccessKeyId=x&Status=On",
            "ValidationError",
        ),
        ("Action=CreateUser&UserName=a%2A", "InvalidInput"),
        ("Action=CreateAccessKey", "InvalidInput"),
    ] {
        assert_eq!(d.code(&root, body), code, "{body}");
    }

    // The root user, about itself; and STS, for anyone.
    let body = d.ok(&root, "Action=GetUser");
    assert!(body.contains(&format!(
        "<User><UserId>{0}</UserId><Arn>arn:aws:iam::{0}:root</Arn></User>",
        d.account
    )));
    let sts = |identity: &Identity, body: &str| {
        let context = Context::new(identity.principal().clone(), Date::now());
        d.iam.serve_sts(&Call {
            identity,
            context: &context,
            body: body.as_bytes(),
            request_id: "req-2",
        })
    };
    let bob = d.user("bob", NOTHING);
    let reply = sts(
        &d.identity(&bob),
        "Action=GetCallerIdentity&Version=2011-06-15",
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
    let bob_id = d.iam.user("bob").unwrap().id;
    assert!(
        reply.body.contains(&format!(
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
             <GetCallerIdentityResult><Arn>arn:aws:iam::{0}:user/bob</Arn>\
             <UserId>{bob_id}</UserId><Account>{0}</Account></GetCallerIdentityResult>",
            d.account
        )),
        "{}",
        reply.body
    );
    assert_eq!(sts(&root, "Action=AssumeRole").status, 400);
}

#[tokio::test]
async fn documents_and_pages_round_trip() {
    let d = drive().await;
    let root = d.root();
    let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ab/c d*"}]}"#;
    d.ok(
        &root,
        &format!(
            "Action=CreatePolicy&PolicyName=read&PolicyDocument={}&Description=d%C3%A9+%26+%3C",
            enc(document)
        ),
    );
    let arn = d.policy_arn("read");
    let body = d.ok(
        &root,
        &format!(
            "Action=GetPolicyVersion&PolicyArn={}&VersionId=v1",
            enc(&arn)
        ),
    );
    let encoded = between(&body, "<Document>", "</Document>");
    assert!(encoded.starts_with("%7B%22Version%22%3A%222012-10-17%22"));
    assert!(encoded.contains("ab%2Fc%20d%2A"));
    let decoded = percent_encoding::percent_decode_str(encoded)
        .decode_utf8()
        .unwrap();
    assert_eq!(decoded, document);
    let body = d.ok(&root, &format!("Action=GetPolicy&PolicyArn={}", enc(&arn)));
    assert!(body.contains("<Description>dé &amp; &lt;</Description>"));
    assert!(
        body.contains(
            "<DefaultVersionId>v1</DefaultVersionId><AttachmentCount>0</AttachmentCount>"
        )
    );

    for i in 0..5 {
        d.iam
            .create_user(&format!("u{i}"), None, &[], None)
            .unwrap();
    }
    let mut seen = Vec::new();
    let mut marker = String::new();
    loop {
        let body = d.ok(&root, &format!("Action=ListUsers&MaxItems=2{marker}"));
        seen.extend(
            body.split("<UserName>")
                .skip(1)
                .map(|s| s[..s.find('<').unwrap()].to_owned()),
        );
        if body.contains("<IsTruncated>false</IsTruncated>") {
            assert!(!body.contains("<Marker>"));
            break;
        }
        marker = format!("&Marker={}", between(&body, "<Marker>", "</Marker>"));
    }
    assert_eq!(seen, ["u0", "u1", "u2", "u3", "u4"]);
}

/// Every parameter any action needs, naming things that exist.
fn every_parameter(d: &Drive, key: &str) -> String {
    let arn = enc(&d.policy_arn("managed"));
    format!(
        "UserName=target&GroupName=group&PolicyArn={arn}&PolicyName=inline\
         &PolicyDocument={}&AccessKeyId={key}&Status=Inactive&VersionId=v1\
         &PermissionsBoundary={arn}&Tags.member.1.Key=k&Tags.member.1.Value=v\
         &TagKeys.member.1=k&NewPath=%2Fmoved%2F",
        enc(ALLOW_ALL)
    )
}

#[tokio::test]
async fn every_action_is_authorized() {
    let d = drive().await;
    d.iam.create_user("target", None, &[], None).unwrap();
    let key = d.iam.create_access_key("target").unwrap().info.id;
    d.iam.create_group("group", None).unwrap();
    d.iam
        .create_policy("managed", None, None, ALLOW_ALL, &[])
        .unwrap();
    let nobody = d.identity(&d.user("nobody", NOTHING));
    let params = every_parameter(&d, &key);
    for action in ACTIONS {
        let reply = d.call(&nobody, &format!("Action={}&{params}", action.name));
        assert_eq!(reply.status, 403, "{}: {}", action.name, reply.body);
        assert!(
            reply.body.contains(&format!(
                "<Code>AccessDenied</Code><Message>User: arn:aws:iam::{}:user/nobody is not \
                 authorized to perform: iam:{}",
                d.account, action.name
            )),
            "{}",
            reply.body
        );
    }
    assert_eq!(d.iam.users(None).unwrap().len(), 2, "nothing changed");
    assert!(d.iam.access_key(&key).unwrap().active);

    // With every permission, none is refused (some fail for other reasons).
    let admin = d.identity(&d.user("admin", ALLOW_ALL));
    for action in ACTIONS {
        let reply = d.call(&admin, &format!("Action={}&{params}", action.name));
        assert_ne!(reply.status, 403, "{}: {}", action.name, reply.body);
    }
}

#[tokio::test]
async fn names_resolve_to_their_own_arn_before_policies_decide() {
    let d = drive().await;
    d.iam
        .create_user("Admin", Some("/ops/"), &[], None)
        .unwrap();
    d.iam.create_user("plain", None, &[], None).unwrap();
    let caller = d.identity(&d.user(
        "caller",
        &policy(&[
            statement("Allow", "iam:*", "*", ""),
            statement("Deny", "iam:*", "arn:aws:iam::*:user/ops/*", ""),
        ]),
    ));
    // `admin` is the user at /ops/Admin, whatever the case it's named in.
    for name in ["Admin", "admin", "ADMIN"] {
        assert_eq!(
            d.code(&caller, &format!("Action=DeleteUser&UserName={name}")),
            "AccessDenied",
            "{name}"
        );
    }
    // Moving a user needs the permission on its new ARN too.
    assert_eq!(
        d.code(
            &caller,
            "Action=UpdateUser&UserName=plain&NewPath=%2Fops%2F"
        ),
        "AccessDenied"
    );
    d.ok(
        &caller,
        "Action=UpdateUser&UserName=plain&NewUserName=plain2",
    );
    assert_eq!(d.iam.user("plain2").unwrap().path, "/");
}

#[tokio::test]
async fn users_act_on_themselves_when_they_name_no_one() {
    let d = drive().await;
    let own = "arn:aws:iam::*:user/${aws:username}";
    let key = d.user(
        "bob",
        &policy(&[
            statement("Allow", "iam:*AccessKey*", own, ""),
            statement("Allow", "iam:GetUser", own, ""),
        ]),
    );
    let bob = d.identity(&key);
    d.iam.create_user("carol", None, &[], None).unwrap();
    let body = d.ok(&bob, "Action=GetUser");
    assert!(body.contains("<UserName>bob</UserName>"));
    let body = d.ok(&bob, "Action=ListAccessKeys");
    assert!(body.contains(&format!("<AccessKeyId>{key}</AccessKeyId>")));
    let body = d.ok(&bob, "Action=CreateAccessKey");
    let secret = between(&body, "<SecretAccessKey>", "</SecretAccessKey>");
    let id = between(&body, "<AccessKeyId>", "</AccessKeyId>");
    assert_eq!(d.iam.credential(id).unwrap().secret.as_str(), secret);
    d.ok(
        &bob,
        &format!("Action=UpdateAccessKey&AccessKeyId={id}&Status=Inactive"),
    );
    assert!(d.iam.credential(id).is_none());
    let body = d.ok(
        &bob,
        &format!("Action=GetAccessKeyLastUsed&AccessKeyId={id}"),
    );
    assert!(body.contains("<UserName>bob</UserName><AccessKeyLastUsed><Region>N/A</Region>"));
    assert_eq!(
        d.code(&bob, "Action=GetUser&UserName=carol"),
        "AccessDenied"
    );
    assert_eq!(
        d.code(&bob, "Action=CreateAccessKey&UserName=carol"),
        "AccessDenied"
    );
    let carols = d.iam.create_access_key("carol").unwrap().info.id;
    assert_eq!(
        d.code(
            &bob,
            &format!("Action=GetAccessKeyLastUsed&AccessKeyId={carols}")
        ),
        "AccessDenied"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn iam_condition_keys_hold_back_escalation() {
    let d = drive().await;
    let arn = |name: &str| d.policy_arn(name);
    for name in ["allowed", "admin", "boundary"] {
        d.iam
            .create_policy(name, None, None, ALLOW_ALL, &[])
            .unwrap();
    }
    d.iam.create_user("target", None, &[], None).unwrap();
    let caller = d.identity(&d.user(
        "delegate",
        &policy(&[
            statement(
                "Allow",
                "iam:AttachUserPolicy",
                "*",
                &format!(
                    r#"{{"ArnEquals":{{"iam:PolicyARN":"{}"}}}}"#,
                    arn("allowed")
                ),
            ),
            statement(
                "Allow",
                "iam:CreateUser",
                "*",
                &format!(
                    r#"{{"StringEquals":{{"iam:PermissionsBoundary":"{}"}}}}"#,
                    arn("boundary")
                ),
            ),
            statement(
                "Allow",
                "iam:TagUser",
                "*",
                r#"{"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}"#,
            ),
            statement(
                "Allow",
                "iam:UntagUser",
                "*",
                r#"{"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}"#,
            ),
            statement(
                "Allow",
                "iam:DeleteUser",
                "*",
                r#"{"StringEquals":{"iam:ResourceTag/team":"a"}}"#,
            ),
        ]),
    ));

    // iam:PolicyARN is the policy's own ARN, however the request spells it.
    let attach = |name: &str| {
        format!(
            "Action=AttachUserPolicy&UserName=target&PolicyArn={}",
            enc(&arn(name))
        )
    };
    assert_eq!(d.code(&caller, &attach("admin")), "AccessDenied");
    assert_eq!(d.code(&caller, &attach("ADMIN")), "AccessDenied");
    d.ok(&caller, &attach("ALLOWED"));

    // iam:PermissionsBoundary: only users bounded by `boundary` may be made.
    assert_eq!(
        d.code(&caller, "Action=CreateUser&UserName=free"),
        "AccessDenied"
    );
    let bounded = |name: &str, boundary: &str| {
        format!(
            "Action=CreateUser&UserName={name}&PermissionsBoundary={}",
            enc(&arn(boundary))
        )
    };
    assert_eq!(d.code(&caller, &bounded("x", "admin")), "AccessDenied");
    d.ok(&caller, &bounded("b", "boundary"));

    // Tags given on creation need TagUser too, which aws:TagKeys limits.
    let tagged = |key: &str| {
        format!(
            "{}&Tags.member.1.Key={key}&Tags.member.1.Value=a",
            bounded("t", "boundary")
        )
    };
    assert_eq!(d.code(&caller, &tagged("owner")), "AccessDenied");
    d.ok(&caller, &tagged("team"));

    // aws:TagKeys of an untag are the keys it names.
    d.iam
        .tag_user(
            "target",
            &[("team".into(), "x".into()), ("owner".into(), "y".into())],
        )
        .unwrap();
    assert_eq!(
        d.code(
            &caller,
            "Action=UntagUser&UserName=target&TagKeys.member.1=owner"
        ),
        "AccessDenied"
    );
    d.ok(
        &caller,
        "Action=UntagUser&UserName=target&TagKeys.member.1=team",
    );
    assert_eq!(d.iam.user("target").unwrap().tags.len(), 1);

    // iam:ResourceTag is the user's own tag.
    d.iam.tag_user("b", &[("team".into(), "b".into())]).unwrap();
    assert_eq!(
        d.code(&caller, "Action=DeleteUser&UserName=b"),
        "AccessDenied"
    );
    d.ok(&caller, "Action=DeleteUser&UserName=t");
    assert!(d.iam.user("b").is_ok());
    assert!(d.iam.user("t").is_err());
}
