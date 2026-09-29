//! `AssumeRoleWithWebIdentity`: tokens checked as AWS checks them, trust policies that
//! test the provider's keys, and the sessions they start.

use teifs_policy::Date;

use super::{ALLOW_ALL, Drive, between, code, drive, enc, ok};
use crate::{
    Call, Iam, Identity, NewRole, Owner, Reply,
    oidc::{
        jwt::{self, tests::Signer},
        keys::tests::publishing,
    },
    sessions::now_seconds,
};

const URL: &str = "https://idp.example.com";

/// An identity provider: its signing key, known to the drive as the provider at [`URL`]
/// for the audience `app`.
struct Idp {
    signer: Signer,
}

impl Idp {
    fn new(d: &Drive) -> Self {
        let signer = Signer::rsa();
        d.oidc(URL);
        let keys = jwt::key_set(&format!(r#"{{"keys":[{}]}}"#, signer.jwk("k1", ""))).unwrap();
        d.iam.web_keys.insert(URL, keys);
        Self { signer }
    }

    /// A token for `sub` with the usual claims and `extra` ones (`"amr":["mfa"]`).
    fn token(&self, sub: &str, extra: &str) -> String {
        let now = now_seconds();
        let extra = if extra.is_empty() {
            String::new()
        } else {
            format!(",{extra}")
        };
        self.signer.token(
            "RS256",
            r#""kid":"k1","typ":"JWT""#,
            &format!(
                r#"{{"iss":"{URL}","sub":"{sub}","aud":"app","iat":{now},"exp":{}{extra}}}"#,
                now + 600
            ),
        )
    }
}

fn provider_arn(d: &Drive) -> String {
    d.oidc_arn("idp.example.com")
}

/// A role that the provider's web identities may assume when `condition` holds, with
/// `actions` besides `sts:AssumeRoleWithWebIdentity`; it may do anything.
fn web_role(d: &Drive, name: &str, actions: &[&str], condition: &str) {
    trusting(d, &provider_arn(d), name, actions, condition);
}

/// [`web_role`], for the web identities of the provider `provider` (its ARN).
fn trusting(d: &Drive, provider: &str, name: &str, actions: &[&str], condition: &str) {
    let actions: Vec<String> = ["sts:AssumeRoleWithWebIdentity"]
        .iter()
        .chain(actions)
        .map(|a| format!("\"{a}\""))
        .collect();
    let condition = if condition.is_empty() {
        String::new()
    } else {
        format!(r#","Condition":{condition}"#)
    };
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Federated":"{provider}"}},"Action":[{}]{condition}}}]}}"#,
        actions.join(",")
    );
    d.iam
        .create_role(
            name,
            &NewRole {
                trust: &trust,
                ..NewRole::default()
            },
        )
        .unwrap();
    d.iam
        .put_inline(Owner::Role(name), "all", ALLOW_ALL)
        .unwrap();
}

fn assuming(d: &Drive, role: &str, token: &str, extra: &str) -> String {
    format!(
        "Action=AssumeRoleWithWebIdentity&RoleArn={}&RoleSessionName=s1&WebIdentityToken={}{extra}",
        enc(&d.role_arn(role)),
        enc(token)
    )
}

impl Drive {
    /// An `AssumeRoleWithWebIdentity` request, unsigned.
    fn web(&self, body: &str) -> Reply {
        self.sts(&Identity::anonymous(), body)
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn web_identities_assume_the_roles_their_trust_policies_allow() {
    let d = drive().await;
    let idp = Idp::new(&d);
    let provider = provider_arn(&d);
    web_role(
        &d,
        "ci",
        &[],
        r#"{"StringEquals":{"idp.example.com:aud":"app"},"StringLike":{"idp.example.com:sub":"repo:o/r:*"}}"#,
    );
    let token = idp.token("repo:o/r:ref:refs/heads/main", r#""amr":["pwd","mfa"]"#);
    let body = assuming(&d, "ci", &token, "&DurationSeconds=900");
    let answer = ok(d.web(&body), &body);
    let role_id = d.iam.role("ci").unwrap().id;
    for expected in [
        "<SubjectFromWebIdentityToken>repo:o/r:ref:refs/heads/main</SubjectFromWebIdentityToken>"
            .to_owned(),
        format!(
            "<AssumedRoleUser><AssumedRoleId>{role_id}:s1</AssumedRoleId><Arn>arn:aws:sts::{}:assumed-role/ci/s1</Arn></AssumedRoleUser>",
            d.account
        ),
        format!("<Provider>{provider}</Provider><Audience>app</Audience>"),
    ] {
        assert!(answer.contains(&expected), "{expected} in {answer}");
    }
    assert!(!answer.contains("PackedPolicySize"), "{answer}");
    assert!(!answer.contains("SourceIdentity"), "{answer}");

    // The session is the role's, and its requests have the provider's keys.
    let session = d.session(&answer);
    assert_eq!(
        session.principal().arn(),
        Some(format!("arn:aws:sts::{}:assumed-role/ci/s1", d.account).as_str())
    );
    assert!((890..=900).contains(&(session.session().unwrap().expires() - now_seconds())));
    let context = session.context(Date::now());
    let may = |condition: &str| {
        let policy = teifs_policy::Policy::parse(
            &format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{condition}}}]}}"#
            ),
            teifs_policy::Kind::Identity,
        )
        .unwrap();
        teifs_policy::evaluate(
            &teifs_policy::Policies {
                identity: &[&policy],
                resource: None,
                boundary: None,
                session: None,
            },
            &teifs_policy::Request {
                action: "s3:GetObject",
                resource: "arn:aws:s3:::b/k",
                context: &context,
            },
        )
        .is_allowed()
    };
    for condition in [
        format!(r#"{{"StringEquals":{{"aws:FederatedProvider":"{provider}"}}}}"#),
        r#"{"StringEquals":{"idp.example.com:sub":"repo:o/r:ref:refs/heads/main"}}"#.to_owned(),
        r#"{"StringEquals":{"idp.example.com:aud":"app"}}"#.to_owned(),
        r#"{"ForAnyValue:StringEquals":{"idp.example.com:amr":"mfa"}}"#.to_owned(),
    ] {
        assert!(may(&condition), "{condition}");
    }
    assert!(!may(
        r#"{"StringEquals":{"idp.example.com:sub":"someone else"}}"#
    ));

    // A subject the trust policy doesn't allow, and a role that doesn't exist, are
    // refused alike.
    let other = idp.token("repo:x/y:ref:refs/heads/main", "");
    for body in [
        assuming(&d, "ci", &other, ""),
        assuming(&d, "nobody", &token, ""),
    ] {
        let reply = d.web(&body);
        assert_eq!(code(&reply, &body), "AccessDenied");
        assert!(
            reply
                .body
                .contains("Not authorized to perform sts:AssumeRoleWithWebIdentity"),
            "{}",
            reply.body
        );
    }

    // Whoever signs the request has no part: neither the root user's signature nor a
    // user's whose policy allows everything helps.
    let body = assuming(&d, "ci", &other, "");
    assert_eq!(d.sts_code(&d.root(), &body), "AccessDenied");
    let admin = d.user("admin", ALLOW_ALL);
    assert_eq!(d.sts_code(&d.identity(&admin), &body), "AccessDenied");
    // A trust policy may name only an OpenID Connect provider of the account that
    // exists.
    let missing = format!(
        "Action=CreateRole&RoleName=orphan&AssumeRolePolicyDocument={}",
        enc(&format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Federated":"{}"}},"Action":"sts:AssumeRoleWithWebIdentity"}}]}}"#,
            d.oidc_arn("nowhere.example.com")
        ))
    );
    let reply = d.call(&d.root(), &missing);
    assert_eq!(code(&reply, &missing), "MalformedPolicyDocument");
    assert!(
        reply.body.contains("Invalid principal in policy"),
        "{}",
        reply.body
    );
    // And sessions of every kind may call it.
    let session_body = assuming(&d, "ci", &token, "");
    ok(d.sts(&session, &session_body), &session_body);

    // Session policies narrow it; the role allows at most an hour.
    let body = assuming(
        &d,
        "ci",
        &token,
        &format!(
            "&Policy={}",
            enc(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
            )
        ),
    );
    let answer = ok(d.web(&body), &body);
    assert!(answer.contains("<PackedPolicySize>"), "{answer}");
    let narrowed = d.session(&answer);
    assert!(narrowed.allows(
        &narrowed.context(Date::now()),
        "s3:GetObject",
        "arn:aws:s3:::b/k"
    ));
    assert!(!narrowed.allows(
        &narrowed.context(Date::now()),
        "s3:PutObject",
        "arn:aws:s3:::b/k"
    ));
    let body = assuming(&d, "ci", &token, "&MinimumSessionTokenSize=3000");
    let answer = ok(d.web(&body), &body);
    assert!(between(&answer, "<SessionToken>", "</SessionToken>").len() >= 3000);
    d.session(&answer);
    let body = assuming(&d, "ci", &token, "&DurationSeconds=3601");
    assert_eq!(code(&d.web(&body), &body), "ValidationError");
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn tokens_are_refused_as_aws_refuses_them() {
    let d = drive().await;
    let idp = Idp::new(&d);
    web_role(&d, "ci", &[], "");
    let now = now_seconds();
    let refused = |token: &str| {
        let body = assuming(&d, "ci", token, "");
        let reply = d.web(&body);
        let code = code(&reply, &body);
        let message = between(&reply.body, "<Message>", "</Message>").replace("&apos;", "'");
        (code, message)
    };
    let claims = |claims: &str| {
        idp.signer.token(
            "RS256",
            r#""kid":"k1""#,
            &format!(r#"{{"iss":"{URL}",{claims}}}"#),
        )
    };
    let good = format!(r#""sub":"alice","aud":"app","exp":{}"#, now + 600);
    ok(
        d.web(&assuming(&d, "ci", &claims(&good), "")),
        "a good token",
    );

    for (token, expected_code, expected) in [
        (
            claims(&format!(r#""sub":"alice","aud":"app","exp":{}"#, now - 1)),
            "ExpiredTokenException",
            "Token expired",
        ),
        (
            claims(r#""sub":"alice","aud":"app""#),
            "InvalidIdentityToken",
            "no expiry",
        ),
        (
            claims(&format!(
                r#""sub":"alice","aud":"app","exp":{}.5"#,
                now + 600
            )),
            "InvalidIdentityToken",
            "whole number",
        ),
        (
            claims(&format!(
                r#""sub":"alice","aud":"app","exp":"{}""#,
                now + 600
            )),
            "InvalidIdentityToken",
            "isn't a number",
        ),
        (
            claims(&format!(
                r#""sub":"alice","aud":"other","exp":{}"#,
                now + 600
            )),
            "InvalidIdentityToken",
            "Incorrect token audience",
        ),
        (
            claims(&format!(r#""sub":"alice","exp":{}"#, now + 600)),
            "InvalidIdentityToken",
            "Incorrect token audience",
        ),
        (
            // azp decides, when it's there, whatever aud says.
            claims(&format!(
                r#""sub":"alice","aud":"app","azp":"other","exp":{}"#,
                now + 600
            )),
            "InvalidIdentityToken",
            "Incorrect token audience",
        ),
        (
            claims(&format!(r#""sub":"alice","aud":7,"exp":{}"#, now + 600)),
            "InvalidIdentityToken",
            "aud isn't text",
        ),
        (
            claims(&format!(r#""aud":"app","exp":{}"#, now + 600)),
            "InvalidIdentityToken",
            "no subject",
        ),
        (
            claims(&format!(r#""sub":"","aud":"app","exp":{}"#, now + 600)),
            "InvalidIdentityToken",
            "1 to 255",
        ),
        (
            claims(&format!(
                r#""sub":"alice","aud":"app","exp":{},"nbf":{}"#,
                now + 600,
                now + 120
            )),
            "InvalidIdentityToken",
            "nbf is in the future",
        ),
        (
            claims(&format!(
                r#""sub":"alice","aud":"app","exp":{},"iat":{}"#,
                now + 600,
                now + 120
            )),
            "InvalidIdentityToken",
            "iat is in the future",
        ),
        (
            Signer::rsa().token(
                "RS256",
                r#""kid":"k1""#,
                &format!(r#"{{"iss":"{URL}",{good}}}"#),
            ),
            "InvalidIdentityToken",
            "signature is not valid",
        ),
        (
            idp.signer.token(
                "RS256",
                r#""kid":"k1""#,
                &format!(r#"{{"iss":"https://other.example.com",{good}}}"#),
            ),
            "InvalidIdentityToken",
            "No OpenIDConnect provider found in your account for https://other.example.com",
        ),
        (
            idp.signer
                .token("RS256", r#""kid":"k1""#, &format!("{{{good}}}")),
            "InvalidIdentityToken",
            "names no issuer",
        ),
        (
            idp.signer
                .token("HS256", "", &format!(r#"{{"iss":"{URL}",{good}}}"#)),
            "InvalidIdentityToken",
            "only RS256",
        ),
        (
            "not.a.token".to_owned(),
            "InvalidIdentityToken",
            "header isn't base64url",
        ),
        (
            claims(&format!(
                r#""sub":"alice","aud":"app","exp":{},"https://aws.amazon.com/roles":["arn:aws:iam::{}:role/other"]"#,
                now + 600,
                d.account
            )),
            "InvalidIdentityToken",
            "doesn't name the role",
        ),
    ] {
        let (got, message) = refused(&token);
        assert_eq!(got, expected_code, "{message}");
        assert!(message.contains(expected), "{expected}: {message}");
    }

    // A provider whose keys haven't been fetched can't vouch for anyone yet.
    let second = "https://second.example.com";
    d.oidc(second);
    let token = idp
        .signer
        .token("RS256", "", &format!(r#"{{"iss":"{second}",{good}}}"#));
    let (got, message) = refused(&token);
    assert_eq!(got, "IDPCommunicationError");
    assert!(message.contains("haven't been fetched"), "{message}");

    // Parameters are checked before the token.
    for (extra, expected) in [
        ("&ProviderId=www.amazon.com", "ProviderId"),
        ("&DurationSeconds=899", "durationSeconds"),
    ] {
        let body = assuming(&d, "ci", "abcd", extra);
        let reply = d.web(&body);
        assert_eq!(code(&reply, &body), "ValidationError");
        assert!(reply.body.contains(expected), "{}", reply.body);
    }
    for body in [
        "Action=AssumeRoleWithWebIdentity&RoleSessionName=s1&WebIdentityToken=abcd".to_owned(),
        format!(
            "Action=AssumeRoleWithWebIdentity&RoleArn={}&WebIdentityToken=abcd",
            enc(&d.role_arn("ci"))
        ),
        format!(
            "Action=AssumeRoleWithWebIdentity&RoleArn={}&RoleSessionName=s1",
            enc(&d.role_arn("ci"))
        ),
        assuming(&d, "ci", "abc", ""),
        assuming(&d, "ci", &"a".repeat(jwt::MAX_TOKEN + 1), ""),
    ] {
        assert_eq!(code(&d.web(&body), &body), "ValidationError", "{body}");
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn tokens_carry_roles_session_tags_and_a_source_identity() {
    let d = drive().await;
    let idp = Idp::new(&d);
    let role_arn = d.role_arn("tagged");
    web_role(
        &d,
        "tagged",
        &["sts:TagSession", "sts:SetSourceIdentity"],
        r#"{"Bool":{"sts:RoleAuthorizedByIdp":"true"},"StringEquals":{"aws:RequestTag/team":"data","sts:SourceIdentity":"alice@example.com"}}"#,
    );
    web_role(&d, "plain", &[], "");
    let aws = |roles: &str, tags: &str, source: &str| {
        idp.token(
            "alice",
            &format!(
                r#""https://aws.amazon.com/roles":{roles},"https://aws.amazon.com/tags":{tags},"https://aws.amazon.com/source_identity":"{source}""#
            ),
        )
    };
    let tags =
        r#"{"principal_tags":{"team":["data"],"cost":["42"]},"transitive_tag_keys":["team"]}"#;
    // The roles claim may be a list, or text of ARNs separated by semicolons.
    for roles in [
        format!(r#"["{role_arn}"]"#),
        format!(r#""arn:aws:iam::{}:role/other;{role_arn}""#, d.account),
    ] {
        let token = aws(&roles, tags, "alice@example.com");
        let body = assuming(&d, "tagged", &token, "");
        let answer = ok(d.web(&body), &body);
        assert!(answer.contains("<PackedPolicySize>"), "{answer}");
        assert!(
            answer.contains("<SourceIdentity>alice@example.com</SourceIdentity>"),
            "{answer}"
        );
        let session = d.session(&answer);
        assert_eq!(
            session.session().unwrap().source_identity(),
            Some("alice@example.com")
        );
        assert_eq!(
            session.session().unwrap().transitive_tags(),
            [("team".to_owned(), "data".to_owned())]
        );
        assert!(
            session
                .tags()
                .contains(&("cost".to_owned(), "42".to_owned()))
        );
    }

    // Tags and a source identity need the trust policy's sts:TagSession and
    // sts:SetSourceIdentity.
    let token = aws(
        &format!(r#"["{}"]"#, d.role_arn("plain")),
        tags,
        "alice@example.com",
    );
    let reply = d.web(&assuming(&d, "plain", &token, ""));
    assert!(
        reply
            .body
            .contains("Not authorized to perform sts:TagSession"),
        "{}",
        reply.body
    );
    // A source identity alone needs sts:SetSourceIdentity.
    let token = aws(
        &format!(r#"["{}"]"#, d.role_arn("plain")),
        "{}",
        "alice@example.com",
    );
    let reply = d.web(&assuming(&d, "plain", &token, ""));
    assert!(
        reply
            .body
            .contains("Not authorized to perform sts:SetSourceIdentity"),
        "{}",
        reply.body
    );
    // A token without the roles claim isn't authorized by its provider.
    let token = idp.token(
        "alice",
        &format!(r#""https://aws.amazon.com/tags":{tags},"https://aws.amazon.com/source_identity":"alice@example.com""#),
    );
    assert_eq!(
        code(&d.web(&assuming(&d, "tagged", &token, "")), "no roles"),
        "AccessDenied"
    );

    let roles = format!(r#"["{role_arn}"]"#);
    for (tags, source, expected) in [
        (
            r#"{"principal_tags":{"team":"data"}}"#,
            "alice",
            "other than one text value",
        ),
        (
            r#"{"principal_tags":{"team":["a","b"]}}"#,
            "alice",
            "other than one text value",
        ),
        (
            r#"{"principal_tags":{"team":["a"],"TEAM":["b"]}}"#,
            "alice",
            "twice",
        ),
        (
            r#"{"principal_tags":{"aws:x":["a"]}}"#,
            "alice",
            "AWS refuses",
        ),
        (
            r#"{"principal_tags":{"a":["b"]},"transitive_tag_keys":["c"]}"#,
            "alice",
            "isn't one of its tags",
        ),
        (r#"{"principal_tags":[]}"#, "alice", "aren't an object"),
        ("[]", "alice", "isn't an object"),
        ("{}", "aws:alice", "2 to 64"),
        ("{}", "a", "2 to 64"),
        ("{}", "al ice", "2 to 64"),
    ] {
        let token = aws(&roles, tags, source);
        let body = assuming(&d, "tagged", &token, "");
        let reply = d.web(&body);
        assert_eq!(
            code(&reply, &body),
            "InvalidIdentityToken",
            "{tags} {source}"
        );
        let message = reply.body.replace("&apos;", "'");
        assert!(message.contains(expected), "{expected}: {message}");
    }
    let many: Vec<String> = (0..51).map(|i| format!(r#""k{i}":["v"]"#)).collect();
    let token = aws(
        &roles,
        &format!(r#"{{"principal_tags":{{{}}}}}"#, many.join(",")),
        "alice",
    );
    let reply = d.web(&assuming(&d, "tagged", &token, ""));
    assert!(reply.body.contains("more than 50 tags"), "{}", reply.body);
}

#[tokio::test]
async fn unsigned_requests_fetch_the_providers_keys_first() {
    let d = drive().await;
    let signer = Signer::rsa();
    let provider = publishing(vec![signer.jwk("k1", r#""alg":"RS256","use":"sig""#)], "").await;
    let url = format!("{}/idp", provider.url);
    d.oidc(&url);
    let name = url.trim_start_matches("http://").to_owned();
    trusting(
        &d,
        &d.oidc_arn(&name),
        "ci",
        &[],
        &format!(r#"{{"StringEquals":{{"{name}:sub":"alice"}}}}"#),
    );
    let now = now_seconds();
    let token = signer.token(
        "RS256",
        r#""kid":"k1""#,
        &format!(
            r#"{{"iss":"{url}","sub":"alice","aud":"app","exp":{}}}"#,
            now + 600
        ),
    );
    let body = assuming(&d, "ci", &token, "");
    assert!(Iam::is_web_identity(body.as_bytes()));
    assert!(!Iam::is_web_identity(b"Action=AssumeRole&RoleArn=x"));
    assert!(!Iam::is_web_identity(b"\xff"));

    let anonymous = Identity::anonymous();
    let context = anonymous.context(Date::now());
    let call = Call {
        identity: &anonymous,
        context: &context,
        body: body.as_bytes(),
        request_id: "req-1",
    };
    let answer = ok(d.iam.serve_web_identity(&call).await, &body);
    assert!(
        answer.contains("<SubjectFromWebIdentityToken>alice<"),
        "{answer}"
    );
    // The keys are kept: a second token needs no fetch.
    let before = provider.requests.load(std::sync::atomic::Ordering::SeqCst);
    ok(d.iam.serve_web_identity(&call).await, &body);
    assert_eq!(
        provider.requests.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn without_a_role_tokens_name_the_policies_as_minio_has_it() {
    let d = drive().await;
    let idp = Idp::new(&d);
    let provider = provider_arn(&d);
    let may = |name: &str, document: &str| {
        d.iam
            .create_policy(name, None, None, document, &[])
            .unwrap();
    };
    may(
        "reader",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
    );
    may(
        "writer",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#,
    );
    let body = |token: &str, extra: &str| {
        format!(
            "Action=AssumeRoleWithWebIdentity&WebIdentityToken={}{extra}",
            enc(token)
        )
    };
    let refused = |body: &str, code_is: &str, message: &str| {
        let reply = d.web(body);
        assert_eq!(code(&reply, body), code_is);
        assert!(reply.body.contains(message), "{message} in {}", reply.body);
    };
    let allows = |session: &Identity, action: &str| {
        session.allows(&session.context(Date::now()), action, "arn:aws:s3:::b/k")
    };

    // A provider must let its tokens name policies; else a role is needed, as on AWS.
    let named = idp.token("alice", r#""policy":"reader""#);
    refused(&body(&named, ""), "ValidationError", "roleArn");
    d.iam
        .tag_oidc_provider(
            &provider,
            &[(crate::oidc::POLICY_CLAIM_TAG.to_owned(), String::new())],
        )
        .unwrap();

    // The policies it names, as text separated by commas or a list, by name in any
    // case or by ARN; the ones that don't exist count for nothing.
    let answer = ok(
        d.web(&body(
            &idp.token("alice", r#""policy":"nothing, reader""#),
            "",
        )),
        "reader",
    );
    for expected in [
        "<SubjectFromWebIdentityToken>alice</SubjectFromWebIdentityToken>".to_owned(),
        format!("<Provider>{provider}</Provider><Audience>app</Audience>"),
    ] {
        assert!(answer.contains(&expected), "{expected} in {answer}");
    }
    assert!(!answer.contains("AssumedRoleUser"), "{answer}");
    let session = d.session(&answer);
    assert!(allows(&session, "s3:GetObject"));
    assert!(!allows(&session, "s3:PutObject"));
    assert_eq!(session.session().unwrap().kind(), crate::SessionKind::Web);
    assert!(session.session().unwrap().may_manage());
    // It lasts as long as the token, unless asked.
    assert!((590..=600).contains(&(session.session().unwrap().expires() - now_seconds())));
    let principal = session.principal();
    assert_eq!(principal.account(), Some(d.account.as_str()));
    assert_eq!(principal.user_id(), format!("{provider}:alice"));
    let both = idp.token(
        "bob",
        &format!(r#""policy":["READER","{}"]"#, d.policy_arn("writer")),
    );
    let answer = ok(d.web(&body(&both, "&DurationSeconds=31536000")), "both");
    let session = d.session(&answer);
    assert!(allows(&session, "s3:GetObject") && allows(&session, "s3:PutObject"));
    assert!(session.session().unwrap().expires() - now_seconds() > 31_535_000);

    // Its session may assume a role, as a role's session: a chain, of an hour at most.
    may(
        "assumer",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}"#,
    );
    let trust = d.trust_account();
    d.iam
        .create_role(
            "target",
            &NewRole {
                trust: &trust,
                max_session: Some(7200),
                ..NewRole::default()
            },
        )
        .unwrap();
    let assumer = d.session(&ok(
        d.web(&body(&idp.token("erin", r#""policy":"assumer""#), "")),
        "assumer",
    ));
    let chain = format!(
        "Action=AssumeRole&RoleArn={}&RoleSessionName=s2",
        enc(&d.role_arn("target"))
    );
    d.sts_ok(&assumer, &chain);
    assert_eq!(
        d.sts_code(&assumer, &format!("{chain}&DurationSeconds=3601")),
        "ValidationError"
    );

    // Session policies narrow it; the token may be padded.
    let narrow = body(
        &both,
        &format!(
            "&RoleSessionName=bob&MinimumSessionTokenSize=3000&Policy={}",
            enc(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#
            )
        ),
    );
    let answer = ok(d.web(&narrow), "narrow");
    assert!(between(&answer, "<SessionToken>", "</SessionToken>").len() >= 3000);
    let narrowed = d.session(&answer);
    assert!(!allows(&narrowed, "s3:GetObject") && allows(&narrowed, "s3:PutObject"));

    // A deleted policy takes only its permissions; a deleted provider, the session.
    let key = between(&answer, "<AccessKeyId>", "</AccessKeyId>").to_owned();
    let token = between(&answer, "<SessionToken>", "</SessionToken>").to_owned();
    d.iam.delete_policy(&d.policy_arn("writer")).unwrap();
    let session = d.iam.identify(&key, Some(&token)).unwrap();
    assert!(!allows(&session, "s3:PutObject"));

    // Errors as MinIO's.
    refused(
        &body(&idp.token("carol", ""), ""),
        "InvalidParameterValue",
        "policy claim missing from the JWT token",
    );
    refused(
        &body(&idp.token("carol", r#""policy":"nothing, ,""#), ""),
        "InvalidParameterValue",
        "None of the given policies are defined",
    );
    refused(
        &body(&idp.token("carol", r#""policy":7"#), ""),
        "InvalidParameterValue",
        "a list of text",
    );
    refused(
        &body(&named, "&RoleArn=arn:minio:iam:::role/dummy"),
        "InvalidParameterValue",
        "TeiFS has no MinIO role policies",
    );
    for extra in [
        "&DurationSeconds=899",
        "&DurationSeconds=31536001",
        "&RoleSessionName=a",
    ] {
        refused(&body(&named, extra), "ValidationError", "");
    }

    // The tag's value names another claim.
    d.iam
        .tag_oidc_provider(
            &provider,
            &[(
                crate::oidc::POLICY_CLAIM_TAG.to_owned(),
                "groups".to_owned(),
            )],
        )
        .unwrap();
    refused(
        &body(&named, ""),
        "InvalidParameterValue",
        "groups claim missing",
    );
    let grouped = idp.token("dave", r#""groups":["reader"]"#);
    ok(d.web(&body(&grouped, "")), "groups");

    d.iam.delete_oidc_provider(&provider).unwrap();
    assert!(d.iam.identify(&key, Some(&token)).is_err());
}
