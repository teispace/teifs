#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::{collections::BTreeSet, sync::Arc};

use teifs_crypto::LocalKms;
use teifs_policy::{Date, IamKey};
use zeroize::Zeroizing;

use super::{ACTIONS, Action, On};
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

/// The actions of `actions` are the service's, on the resources and with the condition
/// keys its reference gives, but for the keys of other identity providers (`saml:…`,
/// `accounts.google.com:…`), which no request signed with IAM credentials has. The
/// actions in `minio` are MinIO's own, which AWS doesn't have.
fn check_reference(service: &serde_json::Value, actions: &[Action], minio: &[&str]) {
    let names: BTreeSet<&str> = actions.iter().map(|a| a.name).collect();
    assert_eq!(names.len(), actions.len(), "an action is listed twice");
    for action in actions.iter().filter(|a| !minio.contains(&a.name)) {
        let entry = &service["actions"][action.name];
        assert!(
            entry.is_object(),
            "{} isn't the service's action",
            action.name
        );
        let on = match action.on {
            On::Any => None,
            On::User => Some("user"),
            On::Group => Some("group"),
            On::Role => Some("role"),
            On::Policy => Some("policy"),
            On::OidcProvider => Some("oidc-provider"),
            On::SamlProvider => Some("saml-provider"),
            On::FederatedUser => Some("federated-user"),
        };
        assert_eq!(
            strings(&entry["resources"]),
            on.into_iter().map(str::to_owned).collect(),
            "{}'s resource",
            action.name
        );
        let ours: BTreeSet<String> = action.keys.iter().map(|k| (*k).to_owned()).collect();
        let theirs: BTreeSet<String> = strings(&entry["conditionKeys"])
            .into_iter()
            .filter(|k| ["aws:", "iam:", "sts:"].iter().any(|p| k.starts_with(p)))
            .collect();
        assert_eq!(theirs, ours, "{}'s condition keys", action.name);
    }
}

#[test]
fn actions_match_aws_service_reference() {
    let reference: serde_json::Value = serde_json::from_str(REFERENCE).unwrap();
    check_reference(&reference, ACTIONS, &[]);
    check_reference(
        &reference["sts"],
        super::sts::ACTIONS,
        &[
            super::sts::LDAP_IDENTITY,
            super::sts::CERTIFICATE,
            super::sts::CUSTOM_TOKEN,
            super::sts::CLIENT_GRANTS,
        ],
    );
    let names: BTreeSet<&str> = ACTIONS.iter().map(|a| a.name).collect();
    for action in ACTIONS {
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
    for kind in ["policy", "oidc-provider", "saml-provider"] {
        assert_eq!(
            resource_keys(kind),
            ["aws:ResourceTag/${TagKey}".to_owned()].into(),
            "{kind}"
        );
    }
    assert!(resource_keys("group").is_empty());
    assert_eq!(
        resource_keys("role"),
        ["aws:ResourceTag/${TagKey}", "iam:ResourceTag/${TagKey}"]
            .map(str::to_owned)
            .into()
    );
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
    // And every `sts:` key but `sts:RequestContext/…`, which only `SetContext` sets.
    let ours: BTreeSet<String> = teifs_policy::StsKey::ALL
        .iter()
        .map(|k| k.name().to_owned())
        .chain(["sts:RequestContext/${ContextKey}".to_owned()])
        .collect();
    assert_eq!(ours, strings(&reference["sts"]["conditionKeys"]));
}

struct Drive {
    dir: tempfile::TempDir,
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
    Drive { dir, iam, account }
}

impl Drive {
    /// The drive's IAM as it opens again: what was saved.
    async fn reopened(&self) -> Iam {
        let kms = LocalKms::open(self.dir.path().join("keyring.json")).unwrap();
        Iam::open(&self.dir.path().join("system.db"), "d", &kms, None)
            .await
            .unwrap()
    }

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

    fn serve(&self, api: Api, identity: &Identity, body: &str) -> Reply {
        let context = identity.context(Date::now());
        let call = Call {
            identity,
            context: &context,
            body: body.as_bytes(),
            request_id: "req-1",
            certificates: &[],
        };
        match api {
            Api::Iam => self.iam.serve_iam(&call),
            Api::Sts => self.iam.serve_sts(&call),
        }
    }

    fn call(&self, identity: &Identity, body: &str) -> Reply {
        self.serve(Api::Iam, identity, body)
    }

    fn ok(&self, identity: &Identity, body: &str) -> String {
        ok(self.call(identity, body), body)
    }

    fn code(&self, identity: &Identity, body: &str) -> String {
        code(&self.call(identity, body), body)
    }

    fn sts(&self, identity: &Identity, body: &str) -> Reply {
        self.serve(Api::Sts, identity, body)
    }

    fn sts_ok(&self, identity: &Identity, body: &str) -> String {
        ok(self.sts(identity, body), body)
    }

    fn sts_code(&self, identity: &Identity, body: &str) -> String {
        code(&self.sts(identity, body), body)
    }

    fn oidc_arn(&self, name: &str) -> String {
        format!("arn:aws:iam::{}:oidc-provider/{name}", self.account)
    }

    /// An OpenID Connect provider at `url`, for the audience `app`.
    fn oidc(&self, url: &str) -> crate::OidcProviderInfo {
        self.iam
            .create_oidc_provider(&crate::NewOidcProvider {
                url,
                client_ids: &["app".to_owned()],
                ..crate::NewOidcProvider::default()
            })
            .unwrap()
    }

    fn policy_arn(&self, name: &str) -> String {
        format!("arn:aws:iam::{}:policy/{name}", self.account)
    }

    /// A trust policy that lets the account's own principals assume a role, if their
    /// policies allow them.
    fn trust_account(&self) -> String {
        trust(&format!(
            r#"{{"AWS":"arn:aws:iam::{}:root"}}"#,
            self.account
        ))
    }

    fn role(&self, name: &str) -> crate::RoleInfo {
        self.iam
            .create_role(
                name,
                &crate::NewRole {
                    trust: &self.trust_account(),
                    ..crate::NewRole::default()
                },
            )
            .unwrap()
    }
}

#[derive(Clone, Copy)]
enum Api {
    Iam,
    Sts,
}

fn ok(reply: Reply, body: &str) -> String {
    assert_eq!(reply.status, 200, "{body}: {}", reply.body);
    reply.body
}

fn code(reply: &Reply, body: &str) -> String {
    assert_ne!(reply.status, 200, "{body} succeeded");
    between(&reply.body, "<Code>", "</Code>").to_owned()
}

/// A trust policy that lets `principal` assume the role.
fn trust(principal: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{principal},"Action":"sts:AssumeRole"}}]}}"#
    )
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
        ("Action=CreateInstanceProfile", "InvalidAction"),
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
    let bob = d.user("bob", NOTHING);
    let reply = d.sts(
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
    assert_eq!(d.sts_code(&root, "Action=AssumeRoot"), "InvalidAction");
    assert_eq!(d.sts_code(&root, "Action=ListUsers"), "InvalidAction");
    assert_eq!(d.code(&root, "Action=GetCallerIdentity"), "InvalidAction");
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

#[tokio::test]
async fn built_in_policies_are_listed_by_scope_and_never_changed() {
    let d = drive().await;
    let root = d.root();
    d.ok(
        &root,
        &format!(
            "Action=CreatePolicy&PolicyName=readwrite&PolicyDocument={}",
            enc(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#)
        ),
    );
    let arns = |scope: &str| {
        let mut seen = Vec::new();
        let mut marker = String::new();
        loop {
            let body = d.ok(
                &root,
                &format!("Action=ListPolicies&MaxItems=4{scope}{marker}"),
            );
            seen.extend(
                body.split("<Arn>")
                    .skip(1)
                    .map(|s| s[..s.find('<').unwrap()].to_owned()),
            );
            if body.contains("<IsTruncated>false</IsTruncated>") {
                return seen;
            }
            marker = format!("&Marker={}", between(&body, "<Marker>", "</Marker>"));
        }
    };
    let all = arns("");
    assert_eq!(all.len(), 16, "{all:?}");
    assert_eq!(all, arns("&Scope=All"));
    let both = all.iter().position(|a| a.ends_with("/readwrite")).unwrap();
    assert_eq!(
        all[both..=both + 1],
        [
            d.policy_arn("readwrite"),
            "arn:aws:iam::aws:policy/readwrite".to_owned()
        ]
    );
    assert_eq!(arns("&Scope=Local"), [d.policy_arn("readwrite")]);
    let summary = d.ok(&root, "Action=GetAccountSummary");
    assert!(
        summary.contains("<key>Policies</key><value>1</value>"),
        "only the account's own"
    );
    let aws = arns("&Scope=AWS");
    assert_eq!(aws.len(), 15);
    assert!(aws.contains(&"arn:aws:iam::aws:policy/AdministratorAccess".to_owned()));

    let admin = enc("arn:aws:iam::aws:policy/AdministratorAccess");
    let body = d.ok(&root, &format!("Action=GetPolicy&PolicyArn={admin}"));
    assert!(
        body.contains("<PolicyName>AdministratorAccess</PolicyName>"),
        "{body}"
    );
    let reply = d.call(&root, &format!("Action=DeletePolicy&PolicyArn={admin}"));
    assert_eq!(
        (reply.status, code(&reply, "delete")),
        (403, "AccessDenied".to_owned())
    );
}

/// Every parameter any action needs, naming things that exist.
fn every_parameter(d: &Drive, key: &str) -> String {
    let arn = enc(&d.policy_arn("managed"));
    format!(
        "UserName=target&GroupName=group&RoleName=role&PolicyArn={arn}&PolicyName=inline\
         &PolicyDocument={}&AccessKeyId={key}&Status=Inactive&VersionId=v1\
         &PermissionsBoundary={arn}&Tags.member.1.Key=k&Tags.member.1.Value=v\
         &TagKeys.member.1=k&NewPath=%2Fmoved%2F&AssumeRolePolicyDocument={}\
         &Description=d&MaxSessionDuration=7200&OpenIDConnectProviderArn={}\
         &Url=https%3A%2F%2Fidp.example.com&ClientID=app&ClientIDList.member.1=app\
         &ThumbprintList.member.1={}&Name=new&SAMLMetadataDocument={}&SAMLProviderArn={}",
        enc(ALLOW_ALL),
        enc(&d.trust_account()),
        enc(&d.oidc_arn("idp.example.com")),
        "a".repeat(40),
        enc(&saml::document("https://idp.example.com/saml")),
        enc(&format!("arn:aws:iam::{}:saml-provider/saml", d.account)),
    )
}

#[tokio::test]
async fn every_action_is_authorized() {
    let d = drive().await;
    d.iam.create_user("target", None, &[], None).unwrap();
    let key = d.iam.create_access_key("target").unwrap().info.id;
    d.iam.create_group("group", None).unwrap();
    d.role("role");
    d.oidc("https://idp.example.com");
    d.iam
        .create_saml_provider(&crate::NewSamlProvider {
            name: "saml",
            metadata: &saml::document("https://idp.example.com/saml"),
            ..crate::NewSamlProvider::default()
        })
        .unwrap();
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

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn roles_are_made_changed_and_deleted_as_on_aws() {
    let d = drive().await;
    let root = d.root();
    d.iam
        .create_policy("managed", None, None, ALLOW_ALL, &[])
        .unwrap();
    let arn = enc(&d.policy_arn("managed"));
    let body = d.ok(
        &root,
        &format!(
            "Action=CreateRole&RoleName=Reader&Path=%2Fsvc%2F&Description=reads\
             &MaxSessionDuration=7200&AssumeRolePolicyDocument={}&PermissionsBoundary={arn}\
             &Tags.member.1.Key=team&Tags.member.1.Value=a",
            enc(&d.trust_account())
        ),
    );
    let role_arn = format!("arn:aws:iam::{}:role/svc/Reader", d.account);
    assert!(
        body.contains("<Role><Path>/svc/</Path><RoleName>Reader</RoleName><RoleId>AROA"),
        "{body}"
    );
    assert!(body.contains(&format!("<Arn>{role_arn}</Arn>")));
    assert!(body.contains(&format!(
        "<AssumeRolePolicyDocument>{}</AssumeRolePolicyDocument>",
        super::encoded(&d.trust_account())
    )));
    assert!(body.contains("<Description>reads</Description><MaxSessionDuration>7200"));
    assert!(body.contains("<PermissionsBoundaryArn>arn:aws:iam::"));
    assert!(body.contains("<Tags><member><Key>team</Key><Value>a</Value></member></Tags>"));

    // Names compare without case; lists leave out tags, boundaries and last use.
    let body = d.ok(&root, "Action=GetRole&RoleName=reader");
    assert!(body.contains("<RoleLastUsed></RoleLastUsed>") || body.contains("<RoleLastUsed/>"));
    let body = d.ok(&root, "Action=ListRoles&PathPrefix=%2Fsvc");
    assert!(body.contains("<RoleName>Reader</RoleName>"));
    assert!(!body.contains("<Tags>") && !body.contains("PermissionsBoundary"));
    assert!(
        !d.ok(&root, "Action=ListRoles&PathPrefix=%2Fother")
            .contains("RoleName")
    );

    d.ok(
        &root,
        "Action=UpdateRole&RoleName=Reader&MaxSessionDuration=43200",
    );
    let body = d.ok(
        &root,
        "Action=UpdateRoleDescription&RoleName=Reader&Description=reads+more",
    );
    assert!(body.contains("<Description>reads more</Description><MaxSessionDuration>43200"));
    d.ok(
        &root,
        "Action=TagRole&RoleName=Reader&Tags.member.1.Key=TEAM&Tags.member.1.Value=b",
    );
    let body = d.ok(&root, "Action=ListRoleTags&RoleName=Reader");
    assert!(
        body.contains("<member><Key>TEAM</Key><Value>b</Value></member></Tags>"),
        "tag keys compare without case: {body}"
    );
    d.ok(
        &root,
        "Action=UntagRole&RoleName=Reader&TagKeys.member.1=team",
    );
    assert!(
        !d.ok(&root, "Action=ListRoleTags&RoleName=Reader")
            .contains("<Key>")
    );

    // Its policies, and what they make a DeleteRole or DeletePolicy conflict with.
    d.ok(
        &root,
        &format!("Action=AttachRolePolicy&RoleName=Reader&PolicyArn={arn}"),
    );
    d.ok(
        &root,
        &format!(
            "Action=PutRolePolicy&RoleName=Reader&PolicyName=inline&PolicyDocument={}",
            enc(ALLOW_ALL)
        ),
    );
    let body = d.ok(
        &root,
        &format!("Action=ListEntitiesForPolicy&PolicyArn={arn}"),
    );
    assert!(
        body.contains("<PolicyRoles><member><RoleName>Reader</RoleName><RoleId>AROA"),
        "{body}"
    );
    let body = d.ok(
        &root,
        &format!(
            "Action=ListEntitiesForPolicy&PolicyArn={arn}&PolicyUsageFilter=PermissionsBoundary\
             &EntityFilter=Role"
        ),
    );
    assert!(body.contains("<RoleName>Reader</RoleName>"), "{body}");
    let body = d.ok(
        &root,
        &format!(
            "Action=ListEntitiesForPolicy&PolicyArn={arn}&PolicyUsageFilter=PermissionsPolicy"
        ),
    );
    assert!(body.contains("<RoleName>Reader</RoleName>"), "{body}");
    let body = d.ok(&root, &format!("Action=GetPolicy&PolicyArn={arn}"));
    assert!(
        body.contains(
            "<AttachmentCount>1</AttachmentCount><PermissionsBoundaryUsageCount>1\
             </PermissionsBoundaryUsageCount>"
        ),
        "{body}"
    );
    let body = d.ok(
        &root,
        "Action=GetRolePolicy&RoleName=Reader&PolicyName=inline",
    );
    assert!(body.contains("<RoleName>Reader</RoleName><PolicyName>inline</PolicyName>"));
    assert!(
        d.ok(&root, "Action=ListRolePolicies&RoleName=Reader")
            .contains("<PolicyNames><member>inline</member></PolicyNames>")
    );
    assert!(
        d.ok(&root, "Action=ListAttachedRolePolicies&RoleName=Reader")
            .contains("<PolicyName>managed</PolicyName>")
    );
    let summary = d.ok(&root, "Action=GetAccountSummary");
    for entry in [
        "<key>Roles</key><value>1</value>",
        "<key>RolesQuota</key><value>1000</value>",
        "<key>AssumeRolePolicySizeQuota</key><value>2048</value>",
        "<key>RolePolicySizeQuota</key><value>10240</value>",
    ] {
        assert!(summary.contains(entry), "{entry}");
    }
    assert_eq!(
        d.code(&root, "Action=DeleteRole&RoleName=Reader"),
        "DeleteConflict"
    );
    assert_eq!(
        d.code(&root, &format!("Action=DeletePolicy&PolicyArn={arn}")),
        "DeleteConflict"
    );
    // Each alone is a conflict too.
    d.ok(
        &root,
        &format!("Action=DetachRolePolicy&RoleName=Reader&PolicyArn={arn}"),
    );
    assert_eq!(
        d.code(&root, "Action=DeleteRole&RoleName=Reader"),
        "DeleteConflict"
    );
    d.ok(
        &root,
        "Action=DeleteRolePolicy&RoleName=Reader&PolicyName=inline",
    );
    d.ok(
        &root,
        &format!("Action=AttachRolePolicy&RoleName=Reader&PolicyArn={arn}"),
    );
    assert_eq!(
        d.code(&root, "Action=DeleteRole&RoleName=Reader"),
        "DeleteConflict"
    );
    d.ok(
        &root,
        "Action=DeleteRolePermissionsBoundary&RoleName=Reader",
    );
    assert_eq!(
        d.code(&root, &format!("Action=DeletePolicy&PolicyArn={arn}")),
        "DeleteConflict",
        "still attached to the role"
    );
    d.ok(
        &root,
        &format!("Action=PutRolePermissionsBoundary&RoleName=Reader&PermissionsBoundary={arn}"),
    );
    d.ok(
        &root,
        &format!("Action=DetachRolePolicy&RoleName=Reader&PolicyArn={arn}"),
    );
    assert_eq!(
        d.code(&root, &format!("Action=DeletePolicy&PolicyArn={arn}")),
        "DeleteConflict",
        "still the role's boundary"
    );
    d.ok(
        &root,
        "Action=DeleteRolePermissionsBoundary&RoleName=Reader",
    );
    assert_eq!(
        d.code(
            &root,
            "Action=DeleteRolePermissionsBoundary&RoleName=Reader"
        ),
        "NoSuchEntity"
    );
    d.ok(&root, "Action=DeleteRole&RoleName=reader");
    assert_eq!(
        d.code(&root, "Action=GetRole&RoleName=Reader"),
        "NoSuchEntity"
    );
    d.ok(&root, &format!("Action=DeletePolicy&PolicyArn={arn}"));
}

#[tokio::test]
async fn roles_are_checked_as_aws_checks_them() {
    let d = drive().await;
    let root = d.root();
    d.role("taken");
    let create = |extra: &str, trust: &str| {
        format!(
            "Action=CreateRole&RoleName=r&AssumeRolePolicyDocument={}{extra}",
            enc(trust)
        )
    };
    let account = d.trust_account();
    for (body, code) in [
        (
            create("", &account).replace("RoleName=r", "RoleName=TAKEN"),
            "EntityAlreadyExists",
        ),
        (create("&MaxSessionDuration=3599", &account), "InvalidInput"),
        (
            create("&MaxSessionDuration=43201", &account),
            "InvalidInput",
        ),
        (
            create("&MaxSessionDuration=1h", &account),
            "ValidationError",
        ),
        (create("&Path=nope", &account), "InvalidInput"),
        (
            create(&format!("&Description={}", "x".repeat(1001)), &account),
            "InvalidInput",
        ),
        // A trust policy names principals and sts: actions only, and no Resource.
        (create("", ALLOW_ALL), "MalformedPolicyDocument"),
        (
            create("", &account.replace("sts:AssumeRole", "s3:GetObject")),
            "MalformedPolicyDocument",
        ),
        // AWS resolves the account's users and roles when the policy is set.
        (
            create(
                "",
                &trust(&format!(
                    r#"{{"AWS":"arn:aws:iam::{}:user/ghost"}}"#,
                    d.account
                )),
            ),
            "MalformedPolicyDocument",
        ),
        (
            create(
                "",
                &trust(&format!(
                    r#"{{"AWS":["arn:aws:iam::{}:role/taken","{}"]}}"#,
                    d.account,
                    "x".repeat(2100)
                )),
            ),
            "MalformedPolicyDocument",
        ),
    ] {
        assert_eq!(d.code(&root, &body), code, "{body}");
    }
    let big = trust(&format!(
        r#"{{"AWS":[{}]}}"#,
        vec![format!(r#""arn:aws:iam::{}:role/taken""#, d.account); 50].join(",")
    ));
    assert_eq!(
        d.code(&root, &create("", &big)),
        "LimitExceeded",
        "over 2048"
    );

    // Principals of other accounts, sessions and the account itself aren't looked up.
    d.iam.create_user("alice", None, &[], None).unwrap();
    let named = trust(&format!(
        r#"{{"AWS":["arn:aws:iam::{0}:user/alice","arn:aws:iam::{0}:role/taken",
            "arn:aws:iam::111122223333:user/bob","arn:aws:sts::{0}:assumed-role/taken/s",
            "{0}"]}}"#,
        d.account
    ));
    d.ok(&root, &create("", &named));
    let bound = d
        .iam
        .read(|s| Ok(s.role_named("r")?.principals.clone()))
        .unwrap();
    let alice = d.iam.user("alice").unwrap();
    let taken = d.iam.role("taken").unwrap();
    assert_eq!(
        bound.into_iter().collect::<Vec<_>>(),
        [(taken.arn, taken.id), (alice.arn, alice.id)]
    );
    assert_eq!(
        d.code(
            &root,
            &format!(
                "Action=UpdateAssumeRolePolicy&RoleName=r&PolicyDocument={}",
                enc(&trust(&format!(
                    r#"{{"AWS":"arn:aws:iam::{}:role/r2"}}"#,
                    d.account
                )))
            )
        ),
        "MalformedPolicyDocument"
    );
    assert_eq!(d.iam.role("r").unwrap().trust, named, "unchanged");
}

#[tokio::test]
async fn role_condition_keys_hold_back_escalation() {
    let d = drive().await;
    for name in ["boundary", "other"] {
        d.iam
            .create_policy(name, None, None, ALLOW_ALL, &[])
            .unwrap();
    }
    let boundary = d.policy_arn("boundary");
    let caller = d.identity(&d.user(
        "delegate",
        &policy(&[
            // Only roles bounded by `boundary`, and only their inline policies.
            statement(
                "Allow",
                "iam:CreateRole",
                "*",
                &format!(r#"{{"StringEquals":{{"iam:PermissionsBoundary":"{boundary}"}}}}"#),
            ),
            statement(
                "Allow",
                "iam:PutRolePolicy",
                "*",
                &format!(r#"{{"StringEquals":{{"iam:PermissionsBoundary":"{boundary}"}}}}"#),
            ),
            statement(
                "Allow",
                "iam:DeleteRole",
                "*",
                r#"{"StringEquals":{"iam:ResourceTag/team":"a"}}"#,
            ),
            statement(
                "Allow",
                "iam:GetRole",
                "*",
                r#"{"StringEquals":{"aws:ResourceTag/team":"a"}}"#,
            ),
        ]),
    ));
    let create = |name: &str, boundary: &str| {
        format!(
            "Action=CreateRole&RoleName={name}&AssumeRolePolicyDocument={}\
             &PermissionsBoundary={}",
            enc(&d.trust_account()),
            enc(&d.policy_arn(boundary))
        )
    };
    assert_eq!(d.code(&caller, &create("free", "other")), "AccessDenied");
    assert_eq!(
        d.code(
            &caller,
            &create("free", "other").replace("&PermissionsBoundary=", "&Nothing=")
        ),
        "AccessDenied"
    );
    d.ok(&caller, &create("bounded", "boundary"));
    d.role("unbounded");
    let put = |role: &str| {
        format!(
            "Action=PutRolePolicy&RoleName={role}&PolicyName=p&PolicyDocument={}",
            enc(ALLOW_ALL)
        )
    };
    assert_eq!(d.code(&caller, &put("unbounded")), "AccessDenied");
    d.ok(&caller, &put("bounded"));

    // Tags on the role decide through iam:ResourceTag and aws:ResourceTag.
    let tagged = |value: &str| vec![("team".to_owned(), value.to_owned())];
    d.iam.tag_role("unbounded", &tagged("b")).unwrap();
    assert_eq!(
        d.code(&caller, "Action=GetRole&RoleName=unbounded"),
        "AccessDenied"
    );
    assert_eq!(
        d.code(&caller, "Action=DeleteRole&RoleName=unbounded"),
        "AccessDenied"
    );
    d.iam.tag_role("unbounded", &tagged("a")).unwrap();
    d.ok(&caller, "Action=GetRole&RoleName=UNBOUNDED");
    d.ok(&caller, "Action=DeleteRole&RoleName=unbounded");
}

mod assume_saml;
mod oidc;
mod saml;
mod sessions;
mod web_identity;
