#![allow(clippy::unwrap_used, reason = "tests fail on any error")]

use super::{fake::FakePlugin, *};

fn settings(url: &str) -> PluginSettings {
    PluginSettings {
        url: url.to_owned(),
        role_policies: vec!["readonly".into()],
        ..PluginSettings::default()
    }
}

#[test]
fn settings_are_checked_and_the_role_named_as_minio_names_it() {
    // MinIO's default id: the URL's SHA-1, base64url without padding.
    let plugin =
        IdentityPlugin::new(settings("http://localhost:8181/path/to/endpoint"), "").unwrap();
    assert_eq!(
        plugin.role_arn(),
        "arn:minio:iam:::role/idmp-rxYVqKQWe_Z6AVcs4GMZNYBCWE8"
    );
    let mut given = settings("https://idp.example/check?key=secret");
    given.role_id = Some("ci_tokens-1".into());
    given.role_policies = vec!["a, b".into(), "c".into(), " ".into()];
    let plugin = IdentityPlugin::new(given, "us-east-1").unwrap();
    assert_eq!(
        plugin.role_arn(),
        "arn:minio:iam:us-east-1::role/idmp-ci_tokens-1"
    );
    assert_eq!(plugin.role_policies(), ["a", "b", "c"]);
    assert_eq!(plugin.shown_url(), "https://idp.example/check");

    let refused = |s: PluginSettings| IdentityPlugin::new(s, "").unwrap_err();
    assert!(refused(settings("ftp://x")).contains("isn't an http(s) URL"));
    assert!(refused(settings("not a url")).contains("isn't an http(s) URL"));
    assert!(refused(settings("https://u:p@x")).contains("user name or password"));
    let mut none = settings("https://x");
    none.role_policies = vec![" , ".into()];
    assert!(refused(none).contains("name the policies"));
    for bad in ["has space", "", "a/b"] {
        let mut s = settings("https://x");
        s.role_id = Some(bad.into());
        assert!(refused(s).contains("may have only letters"), "{bad}");
    }
}

#[tokio::test]
async fn the_plugin_is_asked_as_minio_asks_it() {
    let fake = FakePlugin::start().await;
    let plugin = IdentityPlugin::new(fake.settings(&["readonly"]), "").unwrap();
    fake.vouch("good", "alice", 3600);
    assert_eq!(
        plugin.authenticate("good").await.unwrap(),
        PluginUser {
            user: "alice".into(),
            max_seconds: 3600
        }
    );
    let seen = fake.seen();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].token.as_deref(), Some("good"));
    assert_eq!(seen[0].authorization.as_deref(), Some(fake::AUTH_TOKEN));

    assert_eq!(
        plugin.authenticate("unknown").await.unwrap_err(),
        PluginError::Denied("unknown token".into())
    );
    fake.answer("teapot", 418, "{}");
    assert_eq!(
        plugin.authenticate("teapot").await.unwrap_err(),
        PluginError::Failed("Invalid status code 418 from auth plugin".into())
    );
    // A redirect isn't followed, even to where the token would be taken.
    fake.answer("moved", 307, &format!("{}&token=good", fake.url()));
    assert_eq!(
        plugin.authenticate("moved").await.unwrap_err(),
        PluginError::Failed("Invalid status code 307 from auth plugin".into())
    );
    for (seconds, ok) in [
        (899, false),
        (900, true),
        (31_536_000, true),
        (31_536_001, false),
    ] {
        fake.vouch("t", "bob", seconds);
        let answer = plugin.authenticate("t").await;
        assert_eq!(answer.is_ok(), ok, "{seconds}: {answer:?}");
        if !ok {
            assert!(answer.unwrap_err().to_string().starts_with(&format!(
                "Plugin returned an invalid validity duration ({seconds})"
            )));
        }
    }
    fake.vouch("nobody", "", 3600);
    assert_eq!(
        plugin.authenticate("nobody").await.unwrap_err(),
        PluginError::NoUser
    );
    fake.answer("garbled", 200, "not json");
    assert!(matches!(
        plugin.authenticate("garbled").await,
        Err(PluginError::Failed(m)) if m.contains("isn't what it should be")
    ));
    fake.answer("silent", 403, "");
    assert!(matches!(
        plugin.authenticate("silent").await,
        Err(PluginError::Failed(m)) if m.contains("refusal isn't what it should be")
    ));
    fake.answer("huge", 200, &"x".repeat(MAX_ANSWER + 1));
    assert!(matches!(
        plugin.authenticate("huge").await,
        Err(PluginError::Failed(m)) if m.contains("too large")
    ));
    plugin.check().await.unwrap();
    assert_eq!(fake.seen().last().unwrap().method, "HEAD");
}

#[tokio::test]
async fn an_unreachable_plugin_is_said_so_without_the_token() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/auth", closed.local_addr().unwrap());
    drop(closed);
    let plugin = IdentityPlugin::new(settings(&url), "").unwrap();
    let err = plugin.authenticate("secret-token").await.unwrap_err();
    assert!(matches!(err, PluginError::Failed(_)), "{err:?}");
    assert!(!err.to_string().contains("secret-token"), "{err}");
    assert!(plugin.check().await.is_err());
}

mod sign_in {
    use std::sync::Arc;

    use teifs_crypto::LocalKms;
    use teifs_policy::Date;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{AuthError, Call, Iam, Identity, Reply, RootKey, SessionKind};

    const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
      "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;

    async fn iam(dir: &std::path::Path) -> Iam {
        let kms = LocalKms::open(dir.join("keyring.json")).unwrap();
        let root = RootKey {
            access_key: "TFROOTKEY".into(),
            secret: Zeroizing::new("root-secret".into()),
        };
        let iam = Iam::open(&dir.join("system.db"), "drive-1", &kms, Some(root))
            .await
            .unwrap();
        iam.create_policy("readphotos", None, None, READ_PHOTOS, &[])
            .unwrap();
        iam
    }

    /// An IAM whose plugin role has `policies`, and the plugin.
    async fn with_plugin(dir: &std::path::Path, policies: &[&str]) -> (Iam, FakePlugin, String) {
        let fake = FakePlugin::start().await;
        let plugin = IdentityPlugin::new(fake.settings(policies), "").unwrap();
        let role = plugin.role_arn().to_owned();
        (iam(dir).await.with_plugin(plugin), fake, role)
    }

    /// Asks for a session with the parameters in `query`.
    async fn sign_in(iam: &Iam, query: &str) -> Reply {
        let body = format!("Action=AssumeRoleWithCustomToken&Version=2011-06-15{query}");
        assert!(Iam::proves_itself(body.as_bytes()));
        let identity = Identity::anonymous();
        let context = identity.context(Date::now());
        iam.serve_self_proving(&Call {
            identity: &identity,
            context: &context,
            body: body.as_bytes(),
            request_id: "test",
            certificates: &[],
        })
        .await
    }

    fn element<'a>(body: &'a str, name: &str) -> &'a str {
        let start = body.find(&format!("<{name}>")).unwrap() + name.len() + 2;
        let end = start + body[start..].find(&format!("</{name}>")).unwrap();
        &body[start..end]
    }

    fn refusal(reply: &Reply) -> (u16, &str, &str) {
        (
            reply.status,
            element(&reply.body, "Code"),
            element(&reply.body, "Message"),
        )
    }

    fn identity(iam: &Iam, reply: &Reply) -> Result<Arc<Identity>, AuthError> {
        assert_eq!(reply.status, 200, "{}", reply.body);
        iam.identify(
            element(&reply.body, "AccessKeyId"),
            Some(element(&reply.body, "SessionToken")),
        )
    }

    fn allows(identity: &Identity, action: &str, resource: &str) -> bool {
        identity.allows(&identity.context(Date::now()), action, resource)
    }

    fn left(identity: &Identity) -> i64 {
        identity.session().unwrap().expires() - crate::sessions::now_seconds()
    }

    #[tokio::test]
    async fn a_vouched_for_user_gets_the_roles_policies() {
        let dir = tempfile::tempdir().unwrap();
        let (iam, fake, role) = with_plugin(dir.path(), &["ReadPhotos", "missing"]).await;
        fake.vouch("good", "alice", 7200);
        let reply = sign_in(&iam, &format!("&RoleArn={role}&Token=good")).await;
        assert!(reply.body.contains("<AssumeRoleWithCustomTokenResponse"));
        assert_eq!(element(&reply.body, "AssumedUser"), "custom:alice");
        let session = identity(&iam, &reply).unwrap();
        assert_eq!(session.session().unwrap().kind(), SessionKind::Custom);
        assert!(session.session().unwrap().may_manage());
        assert!(allows(&session, "s3:GetObject", "arn:aws:s3:::photos/a"));
        assert!(!allows(&session, "s3:PutObject", "arn:aws:s3:::photos/a"));
        assert!((7190..=7200).contains(&left(&session)));
        assert_eq!(fake.seen().len(), 1);

        // A session policy narrows it.
        let narrowed = sign_in(
            &iam,
            &format!(
                "&RoleArn={role}&Token=good&Policy=%7B%22Version%22%3A%222012-10-17%22%2C\
                 %22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A\
                 %22s3%3AGetObject%22%2C%22Resource%22%3A%22arn%3Aaws%3As3%3A%3A%3Aphotos%2Fa%22%7D%5D%7D"
            ),
        )
        .await;
        let narrowed = identity(&iam, &narrowed).unwrap();
        assert!(allows(&narrowed, "s3:GetObject", "arn:aws:s3:::photos/a"));
        assert!(!allows(&narrowed, "s3:GetObject", "arn:aws:s3:::photos/b"));

        // Asking for less than the plugin allows gets less; more gets what it allows.
        let short = sign_in(
            &iam,
            &format!("&RoleArn={role}&Token=good&DurationSeconds=900"),
        )
        .await;
        assert!((890..=900).contains(&left(&identity(&iam, &short).unwrap())));
        let long = sign_in(
            &iam,
            &format!("&RoleArn={role}&Token=good&DurationSeconds=86400"),
        )
        .await;
        assert!((7190..=7200).contains(&left(&identity(&iam, &long).unwrap())));

        // A policy deleted later takes its permissions with it.
        let arn = format!("arn:aws:iam::{}:policy/readphotos", iam.account());
        iam.delete_policy(&arn).unwrap();
        let fresh = identity(&iam, &reply).unwrap();
        assert!(!allows(&fresh, "s3:GetObject", "arn:aws:s3:::photos/a"));
    }

    #[tokio::test]
    async fn requests_are_checked_before_the_plugin_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let (other, third) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (iam, fake, role) = with_plugin(dir.path(), &["readphotos"]).await;
        fake.vouch("good", "alice", 3600);
        let invalid = |message: &str| (400, "InvalidParameterValue".to_owned(), message.to_owned());
        let refused = |reply: Reply| {
            let (status, code, message) = refusal(&reply);
            (status, code.to_owned(), message.to_owned())
        };
        assert_eq!(
            refused(sign_in(&iam, &format!("&RoleArn={role}")).await),
            invalid("Invalid empty `Token` parameter provided")
        );
        assert_eq!(
            refused(sign_in(&iam, "&RoleArn=arn:minio:iam:::role/idmp-other&Token=good").await),
            invalid(
                "Error processing parameter RoleArn: RoleARN arn:minio:iam:::role/idmp-other \
                 is not defined."
            )
        );
        let reply = sign_in(
            &iam,
            &format!("&RoleArn={role}&Token=good&DurationSeconds=899"),
        )
        .await;
        assert_eq!(refusal(&reply).1, "ValidationError");
        assert_eq!(fake.seen().len(), 0, "the plugin was asked");

        let (unmapped, fake, role) = with_plugin(other.path(), &["a", "b"]).await;
        assert_eq!(
            refused(sign_in(&unmapped, &format!("&RoleArn={role}&Token=good")).await),
            invalid(
                "None of the given policies (`a,b`) are defined, credentials will not be generated"
            )
        );
        assert_eq!(fake.seen().len(), 0, "the plugin was asked");

        let none = self::iam(third.path()).await;
        assert_eq!(
            refusal(&sign_in(&none, "&RoleArn=x&Token=good").await),
            (
                503,
                "STSNotInitialized",
                "STS API &apos;AssumeRoleWithCustomToken&apos; is disabled"
            )
        );
    }

    #[tokio::test]
    async fn the_plugins_refusals_are_passed_on() {
        let dir = tempfile::tempdir().unwrap();
        let (iam, fake, role) = with_plugin(dir.path(), &["readphotos"]).await;
        let ask =
            async |token: &str| sign_in(&iam, &format!("&RoleArn={role}&Token={token}")).await;
        assert_eq!(
            refusal(&ask("unknown").await),
            (403, "AccessDenied", "unknown token")
        );
        fake.answer("teapot", 418, "{}");
        assert_eq!(
            refusal(&ask("teapot").await),
            (
                400,
                "InvalidParameterValue",
                "Invalid status code 418 from auth plugin"
            )
        );
        fake.vouch("nobody", "", 3600);
        assert_eq!(
            refusal(&ask("nobody").await),
            (
                500,
                "InternalError",
                "A valid user was not returned by the authenticator."
            )
        );
        // Signed by anyone, it's still the token that counts.
        drop(fake);
        assert_eq!(refusal(&ask("good").await).1, "InvalidParameterValue");
    }
}
