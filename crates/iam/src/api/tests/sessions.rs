//! STS: temporary credentials, whom they act as, and what they may do.

use std::sync::Arc;

use teifs_policy::Date;

use super::{ALLOW_ALL, Drive, NOTHING, between, drive, enc, policy, statement, trust};
use crate::{AuthError, Identity, NewRole, Owner, SessionKind, sessions::now_seconds};

/// Temporary credentials from an answer.
struct Creds {
    key: String,
    token: String,
}

fn creds(body: &str) -> Creds {
    Creds {
        key: between(body, "<AccessKeyId>", "</AccessKeyId>").to_owned(),
        token: between(body, "<SessionToken>", "</SessionToken>").to_owned(),
    }
}

impl Drive {
    /// The session an answer's credentials sign as; their secret is the one that checks
    /// their signatures.
    pub(super) fn session(&self, body: &str) -> Arc<Identity> {
        let c = creds(body);
        let secret = between(body, "<SecretAccessKey>", "</SecretAccessKey>");
        assert_eq!(self.iam.secret(&c.key).unwrap().as_str(), secret);
        self.iam.identify(&c.key, Some(&c.token)).unwrap()
    }

    pub(super) fn role_arn(&self, name: &str) -> String {
        format!("arn:aws:iam::{}:role/{name}", self.account)
    }

    /// `AssumeRole` of `role` as session `s1`, with `extra` parameters.
    fn assume(&self, identity: &Identity, role: &str, extra: &str) -> String {
        self.sts_ok(identity, &assuming(self, role, "s1", extra))
    }

    /// A role whose trust policy lets the account's principals assume it, tag the session
    /// and set its source identity, if their policies allow them; it may do anything.
    fn open_role(&self, name: &str) {
        let trust = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{}"}},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}}]}}"#,
            self.account
        );
        self.iam
            .create_role(
                name,
                &NewRole {
                    trust: &trust,
                    ..NewRole::default()
                },
            )
            .unwrap();
        self.iam
            .put_inline(Owner::Role(name), "all", ALLOW_ALL)
            .unwrap();
    }
}

fn assuming(d: &Drive, role: &str, name: &str, extra: &str) -> String {
    format!(
        "Action=AssumeRole&RoleArn={}&RoleSessionName={name}{extra}",
        enc(&d.role_arn(role))
    )
}

fn may(identity: &Identity, action: &str, resource: &str) -> bool {
    identity.allows(&identity.context(Date::now()), action, resource)
}

/// How many seconds the session has left.
fn lasts(identity: &Identity) -> i64 {
    identity.session().unwrap().expires() - now_seconds()
}

fn allow(actions: &[&str]) -> String {
    policy(
        &actions
            .iter()
            .map(|action| statement("Allow", action, "*", ""))
            .collect::<Vec<_>>(),
    )
}

#[tokio::test]
async fn assumed_roles_act_as_the_role_until_they_expire_or_it_goes() {
    let d = drive().await;
    d.role("reader");
    d.iam
        .put_inline(
            Owner::Role("reader"),
            "p",
            &policy(&[statement("Allow", "s3:GetObject", "arn:aws:s3:::b/*", "")]),
        )
        .unwrap();
    let alice_key = d.user(
        "alice",
        &policy(&[statement(
            "Allow",
            "sts:AssumeRole",
            &d.role_arn("reader"),
            "",
        )]),
    );
    let alice = d.identity(&alice_key);
    let body = d.assume(&alice, "reader", "");
    let role = d.iam.role("reader").unwrap();
    assert!(
        body.starts_with(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AssumeRoleResponse \
             xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult>\
             <Credentials><AccessKeyId>TSIA"
        ),
        "{body}"
    );
    let size = creds(&body).token.len();
    assert!(
        body.contains(&format!(
            "</SessionTokenUtilization><SessionTokenSize>{size}</SessionTokenSize>\
             <AssumedRoleUser>\
             <AssumedRoleId>{}:s1</AssumedRoleId>\
             <Arn>arn:aws:sts::{}:assumed-role/reader/s1</Arn></AssumedRoleUser>\
             </AssumeRoleResult>",
            role.id, d.account
        )),
        "{body}"
    );
    let utilization: usize = between(&body, "<SessionTokenUtilization>", "<")
        .parse()
        .unwrap();
    assert!((1..100).contains(&utilization), "{body}");
    let c = creds(&body);
    assert_eq!(c.key.len(), 20);
    let session = d.session(&body);
    assert_eq!(
        session.principal().arn(),
        Some(&*format!(
            "arn:aws:sts::{}:assumed-role/reader/s1",
            d.account
        ))
    );
    let s = session.session().unwrap();
    assert_eq!(s.kind(), SessionKind::Role { chained: false });
    assert!((3595..=3600).contains(&lasts(&session)));
    // The role's permissions, not the caller's.
    assert!(may(&session, "s3:GetObject", "arn:aws:s3:::b/x"));
    assert!(!may(&session, "s3:GetObject", "arn:aws:s3:::c/x"));
    assert!(!may(&session, "sts:AssumeRole", &d.role_arn("reader")));
    let who = d.sts_ok(&session, "Action=GetCallerIdentity");
    assert!(
        who.contains(&format!(
            "<Arn>arn:aws:sts::{0}:assumed-role/reader/s1</Arn><UserId>{1}:s1</UserId>\
             <Account>{0}</Account>",
            d.account, role.id
        )),
        "{who}"
    );

    // A token works only with its own key, whole and unchanged.
    let other = creds(&d.assume(&alice, "reader", ""));
    let refused = |key: &str, token: Option<&str>| d.iam.identify(key, token).unwrap_err();
    assert_eq!(refused(&c.key, Some(&other.token)), AuthError::InvalidToken);
    assert_eq!(refused(&other.key, Some(&c.token)), AuthError::InvalidToken);
    assert_eq!(refused(&c.key, None), AuthError::InvalidToken);
    let mut tampered = c.token.clone().into_bytes();
    tampered[40] = if tampered[40] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    assert_eq!(refused(&c.key, Some(&tampered)), AuthError::InvalidToken);
    assert_eq!(
        refused(&c.key, Some("not base64!")),
        AuthError::InvalidToken
    );
    assert_eq!(refused(&c.key, Some("")), AuthError::InvalidToken);
    assert_eq!(refused(&alice_key, Some(&c.token)), AuthError::InvalidToken);
    assert_eq!(refused("AKIANOSUCHKEY", None), AuthError::UnknownKey);
    // The cached identity is the token's too: a second look gives the same one.
    assert!(Arc::ptr_eq(
        &d.iam.identify(&c.key, Some(&c.token)).unwrap(),
        &d.iam.identify(&c.key, Some(&c.token)).unwrap()
    ));
    assert_eq!(refused(&c.key, Some(&other.token)), AuthError::InvalidToken);

    // They expire.
    let expires = s.expires();
    assert!(
        d.iam
            .identify_at(&c.key, Some(&c.token), expires - 1)
            .is_ok()
    );
    assert_eq!(
        d.iam
            .identify_at(&c.key, Some(&c.token), expires)
            .unwrap_err(),
        AuthError::ExpiredToken
    );

    // The role's permissions as they are now; none once it's gone, even if it's made
    // again.
    d.iam.delete_inline(Owner::Role("reader"), "p").unwrap();
    let session = d.iam.identify(&c.key, Some(&c.token)).unwrap();
    assert!(!may(&session, "s3:GetObject", "arn:aws:s3:::b/x"));
    d.iam.delete_role("reader").unwrap();
    assert_eq!(refused(&c.key, Some(&c.token)), AuthError::Revoked);
    d.role("reader");
    assert_eq!(refused(&c.key, Some(&c.token)), AuthError::Revoked);
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn trust_policies_decide_who_may_assume_a_role() {
    let d = drive().await;
    let alice_key = d.user("alice", NOTHING);
    let alice = d.identity(&alice_key);
    let alice_arn = format!("arn:aws:iam::{}:user/alice", d.account);
    let named = trust(&format!(r#"{{"AWS":"{alice_arn}"}}"#));
    let new = |name: &str, trust: &str| {
        d.iam
            .create_role(
                name,
                &NewRole {
                    trust,
                    ..NewRole::default()
                },
            )
            .unwrap();
    };
    let denied = |identity: &Identity, role: &str, extra: &str| {
        assert_eq!(
            d.sts_code(identity, &assuming(&d, role, "s1", extra)),
            "AccessDenied",
            "{role}{extra}"
        );
    };

    // Named by the trust policy, a user needs no policy of their own; trusted as one of
    // the account's, it does.
    new("named", &named);
    d.assume(&alice, "named", "");
    d.role("account");
    denied(&alice, "account", "");
    let bob = d.identity(&d.user(
        "bob",
        &policy(&[statement(
            "Allow",
            "sts:AssumeRole",
            "*",
            r#"{"StringEquals":{"aws:ResourceTag/team":"red"}}"#,
        )]),
    ));
    denied(&bob, "account", "");
    d.iam
        .tag_role("account", &[("team".into(), "red".into())])
        .unwrap();
    d.assume(&bob, "account", "");
    // The root user may not assume roles; a missing role is denied, not revealed.
    denied(&d.root(), "named", "");
    denied(&alice, "nobody", "");

    // A user made again under the same name isn't the one the trust policy names, until
    // it is set again.
    d.iam.delete_access_key("alice", &alice_key).unwrap();
    d.iam.delete_inline(Owner::User("alice"), "p").unwrap();
    d.iam.delete_user("alice").unwrap();
    let alice = d.identity(&d.user("alice", NOTHING));
    denied(&alice, "named", "");
    d.iam.update_trust("named", &named).unwrap();
    d.assume(&alice, "named", "");

    // Conditions on the external id.
    let only = |actions: &str, condition: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{alice_arn}"}},"Action":{actions}{condition}}}]}}"#
        )
    };
    new(
        "guarded",
        &only(
            r#""sts:AssumeRole""#,
            r#","Condition":{"StringEquals":{"sts:ExternalId":"secret-1"},"StringLike":{"sts:RoleSessionName":"ci-*"}}"#,
        ),
    );
    denied(&alice, "guarded", "");
    denied(&alice, "guarded", "&ExternalId=wrong-1");
    assert_eq!(
        d.sts_code(
            &alice,
            &assuming(&d, "guarded", "dev-1", "&ExternalId=secret-1")
        ),
        "AccessDenied"
    );
    d.sts_ok(
        &alice,
        &assuming(&d, "guarded", "ci-1", "&ExternalId=secret-1"),
    );

    // Session tags need sts:TagSession, a source identity sts:SetSourceIdentity.
    let tagged = "&Tags.member.1.Key=team&Tags.member.1.Value=red";
    denied(&alice, "named", tagged);
    denied(&alice, "named", "&SourceIdentity=alice-laptop");
    d.iam
        .update_trust(
            "named",
            &only(
                r#"["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]"#,
                r#","Condition":{"StringEqualsIfExists":{"aws:RequestTag/team":"red"}}"#,
            ),
        )
        .unwrap();
    denied(
        &alice,
        "named",
        "&Tags.member.1.Key=team&Tags.member.1.Value=blue",
    );
    let body = d.assume(
        &alice,
        "named",
        &format!("{tagged}&SourceIdentity=alice-laptop"),
    );
    assert!(body.contains("<PackedPolicySize>"), "{body}");
    assert!(body.contains("<SourceIdentity>alice-laptop</SourceIdentity>"));
    let session = d.session(&body);
    assert_eq!(session.tags(), [("team".to_owned(), "red".to_owned())]);
    assert_eq!(
        session.session().unwrap().source_identity(),
        Some("alice-laptop")
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn sessions_are_limited_and_chained_as_on_aws() {
    let d = drive().await;
    d.open_role("wide");
    d.open_role("next");
    let alice = d.identity(&d.user("alice", &allow(&["sts:*"])));
    for (extra, code) in [
        ("&DurationSeconds=899", "ValidationError"),
        ("&DurationSeconds=43201", "ValidationError"),
        ("&DurationSeconds=3601", "ValidationError"),
        ("&DurationSeconds=x", "ValidationError"),
    ] {
        assert_eq!(
            d.sts_code(&alice, &assuming(&d, "wide", "s1", extra)),
            code,
            "{extra}"
        );
    }
    d.iam.update_role("wide", None, Some(7200)).unwrap();
    // An hour unless asked for longer, whatever the role allows.
    let default = d.session(&d.assume(&alice, "wide", ""));
    assert!((3595..=3600).contains(&lasts(&default)));
    let long = d.session(&d.assume(&alice, "wide", "&DurationSeconds=7200"));
    assert!((7195..=7200).contains(&lasts(&long)));

    // Session policies narrow the role's permissions to what one of them allows.
    let only_get = allow(&["s3:GetObject"]);
    let body = d.assume(&alice, "wide", &format!("&Policy={}", enc(&only_get)));
    assert!(body.contains("<PackedPolicySize>"), "{body}");
    let session = d.session(&body);
    assert!(may(&session, "s3:GetObject", "arn:aws:s3:::b/x"));
    assert!(!may(&session, "s3:PutObject", "arn:aws:s3:::b/x"));
    d.iam
        .create_policy("put", None, None, &allow(&["s3:PutObject"]), &[])
        .unwrap();
    let put = format!("&PolicyArns.member.1.arn={}", enc(&d.policy_arn("put")));
    let session = d.session(&d.assume(&alice, "wide", &put));
    assert!(may(&session, "s3:PutObject", "arn:aws:s3:::b/x"));
    assert!(!may(&session, "s3:GetObject", "arn:aws:s3:::b/x"));
    let session = d.session(&d.assume(&alice, "wide", &format!("{put}&Policy={}", enc(&only_get))));
    assert!(may(&session, "s3:PutObject", "arn:aws:s3:::b/x"));
    assert!(may(&session, "s3:GetObject", "arn:aws:s3:::b/x"));
    assert!(!may(&session, "s3:DeleteObject", "arn:aws:s3:::b/x"));
    for (extra, code) in [
        (
            format!("&PolicyArns.member.1.arn={}", enc(&d.policy_arn("nobody"))),
            "MalformedPolicyDocument",
        ),
        (format!("&Policy={}", enc("{")), "MalformedPolicyDocument"),
        (
            format!(
                "&Policy={}",
                enc(&format!("{only_get}{}", " ".repeat(2049)))
            ),
            "ValidationError",
        ),
        (
            (1..=11)
                .map(|i| format!("&PolicyArns.member.{i}.arn={}", enc(&d.policy_arn("put"))))
                .collect::<Vec<_>>()
                .concat(),
            "ValidationError",
        ),
        (
            (1..=50)
                .map(|i| {
                    format!(
                        "&Tags.member.{i}.Key=k{i}&Tags.member.{i}.Value={}",
                        "v".repeat(256)
                    )
                })
                .collect::<Vec<_>>()
                .concat(),
            "PackedPolicyTooLarge",
        ),
    ] {
        assert_eq!(
            d.sts_code(&alice, &assuming(&d, "wide", "s1", &extra)),
            code,
            "{extra}"
        );
    }

    // A role's session may assume another role for at most an hour; its transitive tags
    // and source identity pass on and can't be changed.
    let wide = d.session(&d.assume(
        &alice,
        "wide",
        "&SourceIdentity=alice-1&Tags.member.1.Key=team&Tags.member.1.Value=red\
         &Tags.member.2.Key=env&Tags.member.2.Value=dev&TransitiveTagKeys.member.1=team",
    ));
    assert_eq!(wide.tags().len(), 2);
    d.iam.update_role("next", None, Some(7200)).unwrap();
    let body = d.sts_ok(&wide, &assuming(&d, "next", "t1", ""));
    assert!(body.contains("<SourceIdentity>alice-1</SourceIdentity>"));
    let next = d.session(&body);
    let s = next.session().unwrap();
    assert_eq!(s.kind(), SessionKind::Role { chained: true });
    assert_eq!(next.tags(), [("team".to_owned(), "red".to_owned())]);
    assert_eq!(s.transitive_tags(), next.tags());
    assert_eq!(s.source_identity(), Some("alice-1"));
    // Conditions see the session's source identity and when it was issued.
    let pinned = policy(&[statement(
        "Allow",
        "s3:GetObject",
        "*",
        r#"{"StringEquals":{"aws:SourceIdentity":"alice-1"},"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}"#,
    )]);
    let pinned = d.session(&d.assume(
        &alice,
        "wide",
        &format!("&SourceIdentity=alice-1&Policy={}", enc(&pinned)),
    ));
    assert!(may(&pinned, "s3:GetObject", "arn:aws:s3:::b/x"));
    for extra in [
        "&DurationSeconds=3601",
        "&SourceIdentity=other-1",
        "&Tags.member.1.Key=TEAM&Tags.member.1.Value=blue",
    ] {
        assert_eq!(
            d.sts_code(&wide, &assuming(&d, "next", "t1", extra)),
            "ValidationError",
            "{extra}"
        );
    }
    d.sts_ok(
        &wide,
        &assuming(
            &d,
            "next",
            "t1",
            "&SourceIdentity=alice-1&DurationSeconds=3600",
        ),
    );

    // A role's session manages IAM as far as the role may, but can't start other kinds
    // of session.
    d.ok(&wide, "Action=ListUsers");
    assert_eq!(d.sts_code(&wide, "Action=GetSessionToken"), "AccessDenied");
    assert_eq!(
        d.sts_code(&wide, "Action=GetFederationToken&Name=fed"),
        "AccessDenied"
    );
}

#[tokio::test]
async fn parameters_are_checked_as_aws_checks_them() {
    let d = drive().await;
    d.open_role("wide");
    let alice = d.identity(&d.user("alice", &allow(&["sts:*"])));
    let arn = enc(&d.role_arn("wide"));
    for (body, code) in [
        (
            format!("Action=AssumeRole&RoleArn={arn}"),
            "ValidationError",
        ),
        (assuming(&d, "wide", "a", ""), "ValidationError"),
        (assuming(&d, "wide", "a%2Ab", ""), "ValidationError"),
        (assuming(&d, "wide", &"a".repeat(65), ""), "ValidationError"),
        (
            assuming(&d, "wide", "s1", "&ExternalId=a"),
            "ValidationError",
        ),
        (
            assuming(
                &d,
                "wide",
                "s1",
                &format!("&ExternalId={}", "a".repeat(1225)),
            ),
            "ValidationError",
        ),
        (
            assuming(&d, "wide", "s1", "&SourceIdentity=aws%3Ax"),
            "ValidationError",
        ),
        (
            assuming(
                &d,
                "wide",
                "s1",
                "&Tags.member.1.Key=a&Tags.member.1.Value=1&Tags.member.2.Key=A\
                 &Tags.member.2.Value=2",
            ),
            "ValidationError",
        ),
        (
            assuming(
                &d,
                "wide",
                "s1",
                "&Tags.member.1.Key=aws%3Ax&Tags.member.1.Value=1",
            ),
            "ValidationError",
        ),
        (
            assuming(
                &d,
                "wide",
                "s1",
                "&Tags.member.1.Key=a&Tags.member.1.Value=1&TransitiveTagKeys.member.1=b",
            ),
            "ValidationError",
        ),
        (
            assuming(&d, "wide", "s1", "&SerialNumber=x&TokenCode=123456"),
            "AccessDenied",
        ),
        (
            "Action=GetSessionToken&TokenCode=123456".to_owned(),
            "AccessDenied",
        ),
    ] {
        assert_eq!(d.sts_code(&alice, &body), code, "{body}");
    }
    let reply = d.sts(&alice, &assuming(&d, "wide", "a", ""));
    assert!(
        reply.body.contains(
            "<Message>1 validation error detected: Value &apos;a&apos; at \
             &apos;roleSessionName&apos; failed to satisfy constraint: Member must have \
             length greater than or equal to 2</Message>"
        ),
        "{}",
        reply.body
    );
    // Names up to their longest, and every character they allow.
    d.sts_ok(
        &alice,
        &assuming(
            &d,
            "wide",
            &"a".repeat(64),
            &format!("&ExternalId={}", enc("Az09_+=,.@:/-")),
        ),
    );
    d.sts_ok(&alice, &assuming(&d, "wide", &enc("Az09_+=,.@-"), ""));
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn session_tokens_and_federated_users_are_limited_as_on_aws() {
    let d = drive().await;
    let alice_policy = allow(&["s3:GetObject", "sts:GetFederationToken", "iam:ListUsers"]);
    let alice = d.identity(&d.user("alice", &alice_policy));
    let alice_arn = format!("arn:aws:iam::{}:user/alice", d.account);

    // GetSessionToken: the user's own permissions, but no IAM and little of STS.
    let body = d.sts_ok(&alice, "Action=GetSessionToken");
    assert!(!body.contains("AssumedRoleUser"), "{body}");
    let token = d.session(&body);
    assert_eq!(token.principal().arn(), Some(alice_arn.as_str()));
    assert_eq!(token.session().unwrap().kind(), SessionKind::SessionToken);
    assert!((43_195..=43_200).contains(&lasts(&token)));
    assert!(may(&token, "s3:GetObject", "arn:aws:s3:::b/x"));
    assert!(!may(&token, "s3:PutObject", "arn:aws:s3:::b/x"));
    d.ok(&alice, "Action=ListUsers");
    assert_eq!(d.code(&token, "Action=ListUsers"), "InvalidClientTokenId");
    for action in [
        "GetSessionToken",
        "GetFederationToken&Name=fed",
        "GetAccessKeyInfo&AccessKeyId=AKIAIOSFODNN7EXAMPLE",
    ] {
        assert_eq!(
            d.sts_code(&token, &format!("Action={action}")),
            "AccessDenied",
            "{action}"
        );
    }
    d.sts_ok(&token, "Action=GetCallerIdentity");
    let token = d.session(&d.sts_ok(&alice, "Action=GetSessionToken&DurationSeconds=129600"));
    assert!((129_595..=129_600).contains(&lasts(&token)));
    for duration in ["899", "129601"] {
        assert_eq!(
            d.sts_code(
                &alice,
                &format!("Action=GetSessionToken&DurationSeconds={duration}")
            ),
            "ValidationError"
        );
    }
    // The root user's lasts an hour at most, and may do anything.
    let root = d.session(&d.sts_ok(&d.root(), "Action=GetSessionToken&DurationSeconds=7200"));
    assert!(root.is_root());
    assert!((3595..=3600).contains(&lasts(&root)));
    assert!(may(&root, "s3:PutObject", "arn:aws:s3:::b/x"));

    // GetFederationToken: allowed by a policy; the federated user may do what both the
    // caller's policies and the session policies allow (none: nothing).
    let bob = d.identity(&d.user("bob", NOTHING));
    assert_eq!(
        d.sts_code(&bob, "Action=GetFederationToken&Name=fed"),
        "AccessDenied"
    );
    let bare = d.session(&d.sts_ok(&alice, "Action=GetFederationToken&Name=fed"));
    assert!(!may(&bare, "s3:GetObject", "arn:aws:s3:::b/x"));
    d.iam
        .tag_user(
            "alice",
            &[("team".into(), "blue".into()), ("env".into(), "dev".into())],
        )
        .unwrap();
    let body = d.sts_ok(
        &alice,
        &format!(
            "Action=GetFederationToken&Name=fed&Policy={}&Tags.member.1.Key=TEAM\
             &Tags.member.1.Value=red",
            enc(&allow(&["s3:*"]))
        ),
    );
    let fed_arn = format!("arn:aws:sts::{0}:federated-user/fed", d.account);
    assert!(
        body.contains(&format!(
            "</SessionTokenSize><FederatedUser><FederatedUserId>{0}:fed</FederatedUserId>\
             <Arn>{fed_arn}</Arn></FederatedUser><PackedPolicySize>",
            d.account
        )),
        "{body}"
    );
    let fed = d.session(&body);
    assert_eq!(fed.principal().arn(), Some(fed_arn.as_str()));
    assert_eq!(fed.session().unwrap().kind(), SessionKind::Federated);
    assert_eq!(
        fed.tags(),
        [
            ("env".to_owned(), "dev".to_owned()),
            ("TEAM".to_owned(), "red".to_owned())
        ]
    );
    assert!(may(&fed, "s3:GetObject", "arn:aws:s3:::b/x"));
    assert!(!may(&fed, "s3:PutObject", "arn:aws:s3:::b/x"));
    assert_eq!(d.code(&fed, "Action=ListUsers"), "InvalidClientTokenId");
    d.open_role("wide");
    assert_eq!(
        d.sts_code(&fed, &assuming(&d, "wide", "s1", "")),
        "AccessDenied"
    );
    let who = d.sts_ok(&fed, "Action=GetCallerIdentity");
    assert!(who.contains(&format!("<UserId>{}:fed</UserId>", d.account)));
    for name in ["f", &"f".repeat(33), "f%2A"] {
        assert_eq!(
            d.sts_code(&alice, &format!("Action=GetFederationToken&Name={name}")),
            "ValidationError",
            "{name}"
        );
    }
    // The root user's federated users have what the session policies allow.
    let ops = d.session(&d.sts_ok(
        &d.root(),
        &format!(
            "Action=GetFederationToken&Name=ops&Policy={}",
            enc(&allow(&["s3:PutObject"]))
        ),
    ));
    assert!(!ops.is_root());
    assert!((3595..=3600).contains(&lasts(&ops)));
    assert!(may(&ops, "s3:PutObject", "arn:aws:s3:::b/x"));
    assert!(!may(&ops, "s3:GetObject", "arn:aws:s3:::b/x"));
    // Even allowed everything, a federated user asks STS only who it is.
    let all = d.session(&d.sts_ok(
        &d.root(),
        &format!(
            "Action=GetFederationToken&Name=all&Policy={}",
            enc(ALLOW_ALL)
        ),
    ));
    assert!(may(&all, "sts:AssumeRole", &d.role_arn("wide")));
    for body in [
        assuming(&d, "wide", "s1", ""),
        "Action=GetAccessKeyInfo&AccessKeyId=AKIAIOSFODNN7EXAMPLE".to_owned(),
    ] {
        assert_eq!(d.sts_code(&all, &body), "AccessDenied", "{body}");
    }

    // GetAccessKeyInfo: the account, to whoever may ask.
    let body = d.sts_ok(
        &d.root(),
        "Action=GetAccessKeyInfo&AccessKeyId=AKIAIOSFODNN7EXAMPLE",
    );
    assert!(body.contains(&format!(
        "<GetAccessKeyInfoResult><Account>{}</Account></GetAccessKeyInfoResult>",
        d.account
    )));
    assert_eq!(
        d.sts_code(
            &bob,
            "Action=GetAccessKeyInfo&AccessKeyId=AKIAIOSFODNN7EXAMPLE"
        ),
        "AccessDenied"
    );
    assert_eq!(
        d.sts_code(&d.root(), "Action=GetAccessKeyInfo&AccessKeyId=short"),
        "ValidationError"
    );
}

#[tokio::test]
async fn minio_assume_role_narrows_the_users_own_permissions() {
    let d = drive().await;
    let alice = d.identity(&d.user("alice", &allow(&["s3:*"])));
    let alice_arn = format!("arn:aws:iam::{}:user/alice", d.account);
    let only_get = enc(&allow(&["s3:GetObject"]));
    for role in [
        "",
        "&RoleArn=arn%3Axxx%3Axxx%3Axxx%3Axxxx",
        "&RoleArn=arn%3Aminio%3Aiam%3A%3A%3Arole%2Fx",
    ] {
        let body = d.sts_ok(
            &alice,
            &format!("Action=AssumeRole{role}&Policy={only_get}"),
        );
        assert!(!body.contains("AssumedRoleUser"), "{body}");
        let session = d.session(&body);
        assert_eq!(session.principal().arn(), Some(alice_arn.as_str()));
        assert_eq!(session.session().unwrap().kind(), SessionKind::User);
        assert!((3595..=3600).contains(&lasts(&session)));
        assert!(may(&session, "s3:GetObject", "arn:aws:s3:::b/x"));
        assert!(!may(&session, "s3:PutObject", "arn:aws:s3:::b/x"));
    }
    let session = d.session(&d.sts_ok(&alice, "Action=AssumeRole&DurationSeconds=31536000"));
    assert!(may(&session, "s3:PutObject", "arn:aws:s3:::b/x"));
    assert!(lasts(&session) > 31_535_000);
    // It may use the IAM API as far as the user may; not start another such session.
    assert_eq!(d.code(&session, "Action=ListUsers"), "AccessDenied");
    for (identity, body, code) in [
        (&session, "Action=AssumeRole", "AccessDenied"),
        (
            &alice,
            "Action=AssumeRole&DurationSeconds=31536001",
            "ValidationError",
        ),
        (
            &alice,
            "Action=AssumeRole&DurationSeconds=899",
            "ValidationError",
        ),
        (&d.root(), "Action=AssumeRole", "AccessDenied"),
        // An AWS ARN is AWS's AssumeRole, which only a role's ARN passes.
        (
            &alice,
            "Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A1%3Auser%2Fx&RoleSessionName=s1",
            "AccessDenied",
        ),
    ] {
        assert_eq!(d.sts_code(identity, body), code, "{body}");
    }
    // A policy that denies sts:AssumeRole denies it.
    let bob = d.identity(&d.user(
        "bob",
        &policy(&[
            statement("Allow", "*", "*", ""),
            statement("Deny", "sts:AssumeRole", "*", ""),
        ]),
    ));
    assert_eq!(d.sts_code(&bob, "Action=AssumeRole"), "AccessDenied");
}
