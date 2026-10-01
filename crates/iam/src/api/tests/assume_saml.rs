//! `AssumeRoleWithSAML`: responses checked as AWS checks them, trust policies that test
//! the `saml:` keys, and the sessions they start.

use teifs_policy::Date;

use super::{ALLOW_ALL, Drive, between, code, drive, enc, ok};
use crate::{
    Identity, NewRole, NewSamlProvider, Owner, Reply,
    saml::response::tests::{ENTITY_ID, Idp, SIGN_IN, Saml, Signed},
    sessions::now_seconds,
};

impl Drive {
    /// An `AssumeRoleWithSAML` request, unsigned.
    fn saml(&self, body: &str) -> Reply {
        self.sts(&Identity::anonymous(), body)
    }

    fn saml_arn(&self, name: &str) -> String {
        format!("arn:aws:iam::{}:saml-provider/{name}", self.account)
    }
}

/// The provider `Okta` for `idp`, and the role `name` it may assume when `condition`
/// holds, with `actions` besides `sts:AssumeRoleWithSAML`; the role may do anything.
fn setup(d: &Drive, idp: &Idp, name: &str, actions: &[&str], condition: &str) {
    if d.iam.saml_provider(&d.saml_arn("Okta")).is_err() {
        d.iam
            .create_saml_provider(&NewSamlProvider {
                name: "Okta",
                metadata: &idp.metadata,
                ..NewSamlProvider::default()
            })
            .unwrap();
    }
    let actions: Vec<String> = ["sts:AssumeRoleWithSAML"]
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
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Federated":"{}"}},"Action":[{}]{condition}}}]}}"#,
        d.saml_arn("Okta"),
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

/// A response for `role` that names it with the provider, for the session `alice`.
fn for_role(d: &Drive, role: &str) -> Saml {
    Saml::default()
        .with(
            "Role",
            &[&format!("{},{}", d.role_arn(role), d.saml_arn("Okta"))],
        )
        .with("RoleSessionName", &["alice"])
}

fn assuming(d: &Drive, role: &str, response: &str, extra: &str) -> String {
    format!(
        "Action=AssumeRoleWithSAML&RoleArn={}&PrincipalArn={}&SAMLAssertion={}{extra}",
        enc(&d.role_arn(role)),
        enc(&d.saml_arn("Okta")),
        enc(response)
    )
}

/// The error `body` gets: its code, and its message contains `words`.
fn refused(d: &Drive, body: &str, code_: &str, words: &str) {
    let reply = d.saml(body);
    assert_eq!(code(&reply, body), code_, "{}", reply.body);
    assert!(reply.body.contains(words), "{words}: {}", reply.body);
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn saml_users_assume_the_roles_their_trust_policies_allow() {
    let d = drive().await;
    let idp = Idp::new();
    setup(
        &d,
        &idp,
        "admins",
        &[],
        &format!(r#"{{"StringEquals":{{"saml:aud":"{SIGN_IN}","saml:sub_type":"persistent"}}}}"#),
    );
    let response = idp.response(&for_role(&d, "admins"));
    let answer = ok(d.saml(&assuming(&d, "admins", &response, "")), "assume");
    let role_id = d.iam.role("admins").unwrap().id;
    let provider = d.iam.saml_provider(&d.saml_arn("Okta")).unwrap();
    let qualifier = {
        use base64::Engine as _;
        let digest = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
            format!("{ENTITY_ID}{}/Okta", d.account).as_bytes(),
        );
        base64::engine::general_purpose::STANDARD.encode(digest)
    };
    for expected in [
        format!(
            "<AssumedRoleUser><AssumedRoleId>{role_id}:alice</AssumedRoleId>\
             <Arn>arn:aws:sts::{}:assumed-role/admins/alice</Arn></AssumedRoleUser>",
            d.account
        ),
        format!(
            "<Subject>alice@example.com</Subject><SubjectType>persistent</SubjectType>\
             <Issuer>{ENTITY_ID}</Issuer><Audience>{SIGN_IN}</Audience>\
             <NameQualifier>{qualifier}</NameQualifier>"
        ),
    ] {
        assert!(answer.contains(&expected), "{expected} in {answer}");
    }
    assert!(!answer.contains("SourceIdentity") && !answer.contains("PackedPolicySize"));

    // The session is the role's for an hour, and its requests have the `saml:` keys.
    let session = d.session(&answer);
    assert!((3590..=3600).contains(&(session.session().unwrap().expires() - now_seconds())));
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
        format!(
            r#"{{"StringEquals":{{"aws:FederatedProvider":"{}"}}}}"#,
            provider.arn
        ),
        r#"{"StringEquals":{"saml:sub":"alice@example.com"}}"#.to_owned(),
        r#"{"StringEquals":{"saml:sub_type":"persistent"}}"#.to_owned(),
        format!(r#"{{"StringEquals":{{"saml:namequalifier":"{qualifier}"}}}}"#),
    ] {
        assert!(may(&condition), "{condition}");
    }
    assert!(!may(r#"{"StringEquals":{"saml:sub":"bob"}}"#));

    // Trust policies decide with the response's keys.
    setup(
        &d,
        &idp,
        "staff",
        &[],
        &format!(
            r#"{{"StringEquals":{{"saml:iss":"{ENTITY_ID}","saml:doc":"{}/Okta","saml:edupersonaffiliation":"staff"}}}}"#,
            d.account
        ),
    );
    let mut staff = for_role(&d, "staff");
    staff.attributes.push((
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.1".into(),
        vec!["staff".into(), "member".into()],
    ));
    ok(
        d.saml(&assuming(&d, "staff", &idp.response(&staff), "")),
        "staff",
    );
    let student = Saml {
        attributes: staff
            .attributes
            .iter()
            .map(|(n, v)| {
                if n.starts_with("urn:oid") {
                    (n.clone(), vec!["student".into()])
                } else {
                    (n.clone(), v.clone())
                }
            })
            .collect(),
        ..staff.clone()
    };
    refused(
        &d,
        &assuming(&d, "staff", &idp.response(&student), ""),
        "AccessDenied",
        "Not authorized to perform sts:AssumeRoleWithSAML",
    );

    // The Role attribute must pair the role with the provider.
    let other_role = Saml::default()
        .with(
            "Role",
            &[&format!("{},{}", d.role_arn("staff"), d.saml_arn("Okta"))],
        )
        .with("RoleSessionName", &["alice"]);
    refused(
        &d,
        &assuming(&d, "admins", &idp.response(&other_role), ""),
        "AccessDenied",
        "Not authorized to perform sts:AssumeRoleWithSAML",
    );
    // Either order, several roles.
    let reversed = Saml::default()
        .with(
            "Role",
            &[
                &format!("{},{}", d.saml_arn("Okta"), d.role_arn("staff")),
                &format!("{},{}", d.saml_arn("Okta"), d.role_arn("admins")),
            ],
        )
        .with("RoleSessionName", &["alice"]);
    ok(
        d.saml(&assuming(&d, "admins", &idp.response(&reversed), "")),
        "reversed",
    );
    // The role must be paired with this provider.
    let elsewhere = Saml::default()
        .with(
            "Role",
            &[&format!(
                "{},{}",
                d.role_arn("admins"),
                d.saml_arn("Okta").replace("Okta", "Other")
            )],
        )
        .with("RoleSessionName", &["alice"]);
    refused(
        &d,
        &assuming(&d, "admins", &idp.response(&elsewhere), ""),
        "AccessDenied",
        "Not authorized to perform sts:AssumeRoleWithSAML",
    );

    // Whoever signs the request has no part.
    let body = assuming(&d, "staff", &idp.response(&student), "");
    assert_eq!(d.sts_code(&d.root(), &body), "AccessDenied");
    // A provider that doesn't exist, and a role that doesn't.
    refused(
        &d,
        &assuming(&d, "admins", &response, "")
            .replace("saml-provider%2FOkta", "saml-provider%2FNone"),
        "InvalidIdentityToken",
        "doesn&apos;t exist",
    );
    refused(
        &d,
        &assuming(&d, "nobody", &idp.response(&for_role(&d, "nobody")), ""),
        "AccessDenied",
        "Not authorized to perform sts:AssumeRoleWithSAML",
    );
    // Deleting the provider ends what it can do.
    d.iam.delete_saml_provider(&d.saml_arn("Okta")).unwrap();
    refused(
        &d,
        &assuming(&d, "admins", &response, ""),
        "InvalidIdentityToken",
        "doesn&apos;t exist",
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "every rule, one after another")]
async fn responses_and_their_attributes_keep_to_aws_rules() {
    let d = drive().await;
    let idp = Idp::new();
    setup(
        &d,
        &idp,
        "r",
        &["sts:TagSession", "sts:SetSourceIdentity"],
        "",
    );
    let good = for_role(&d, "r");
    let body = |saml: &Saml, extra: &str| assuming(&d, "r", &idp.response(saml), extra);

    // Session names.
    let named = |names: &[&str]| {
        let mut saml = good.clone();
        saml.attributes
            .retain(|(n, _)| !n.ends_with("RoleSessionName"));
        if names.is_empty() {
            saml
        } else {
            saml.with("RoleSessionName", names)
        }
    };
    refused(
        &d,
        &body(&named(&[]), ""),
        "InvalidIdentityToken",
        "RoleSessionName is required in AuthnResponse",
    );
    for bad in ["a", "has space", &"n".repeat(65)] {
        refused(
            &d,
            &body(&named(&[bad]), ""),
            "InvalidIdentityToken",
            "RoleSessionName in AuthnResponse must match [a-zA-Z_0-9+=,.@-]{2,64}",
        );
    }
    refused(
        &d,
        &body(&named(&["a1", "b2"]), ""),
        "InvalidIdentityToken",
        "exactly one value",
    );

    // Durations: the shortest of DurationSeconds, SessionDuration, the role's maximum
    // and the provider's session.
    let seconds = |answer: &str| d.session(answer).session().unwrap().expires() - now_seconds();
    let answer = ok(d.saml(&body(&good, "&DurationSeconds=1800")), "1800");
    assert!((1790..=1800).contains(&seconds(&answer)));
    let limited = good.clone().with("SessionDuration", &["900"]);
    let answer = ok(d.saml(&body(&limited, "&DurationSeconds=1800")), "900");
    assert!((890..=900).contains(&seconds(&answer)));
    let ending = Saml {
        session_ends_in: vec![Some(1200)],
        ..good.clone()
    };
    let answer = ok(d.saml(&body(&ending, "")), "ending");
    assert!((1190..=1200).contains(&seconds(&answer)));
    let ended = Saml {
        session_ends_in: vec![Some(600)],
        ..good.clone()
    };
    refused(
        &d,
        &body(&ended, ""),
        "ExpiredTokenException",
        "SessionNotOnOrAfter",
    );
    refused(
        &d,
        &body(&good, "&DurationSeconds=7200"),
        "ValidationError",
        "MaxSessionDuration",
    );
    for bad in ["899", "43201", "x"] {
        refused(
            &d,
            &body(&good.clone().with("SessionDuration", &[bad]), ""),
            "InvalidIdentityToken",
            "SessionDuration",
        );
    }

    // Tags and source identity, which the trust policy must allow.
    let tagged = good
        .clone()
        .with("PrincipalTag:team", &["blue"])
        .with("PrincipalTag:Project", &["x"])
        .with("TransitiveTagKeys", &["team"])
        .with("SourceIdentity", &["alice"]);
    let answer = ok(d.saml(&body(&tagged, "")), "tagged");
    assert!(
        answer.contains("<SourceIdentity>alice</SourceIdentity>"),
        "{answer}"
    );
    assert!(answer.contains("<PackedPolicySize>"), "{answer}");
    let session = d.session(&answer);
    assert_eq!(session.session().unwrap().source_identity(), Some("alice"));
    assert_eq!(
        session.session().unwrap().transitive_tags(),
        [("team".to_owned(), "blue".to_owned())]
    );
    for (saml, words) in [
        (
            good.clone().with("TransitiveTagKeys", &["team"]),
            "isn&apos;t one of the session&apos;s tags",
        ),
        (
            good.clone().with("PrincipalTag:a", &["1", "2"]),
            "exactly one value",
        ),
        (
            good.clone()
                .with("PrincipalTag:a", &["1"])
                .with("PrincipalTag:A", &["2"]),
            "more than once",
        ),
        (
            good.clone().with("SourceIdentity", &["aws:me"]),
            "Source Identity must match",
        ),
    ] {
        refused(&d, &body(&saml, ""), "InvalidIdentityToken", words);
    }
    setup(&d, &idp, "plain", &[], "");
    let plain = Saml {
        attributes: tagged
            .attributes
            .iter()
            .map(|(n, v)| {
                if n.ends_with("/Role") {
                    (
                        n.clone(),
                        vec![format!("{},{}", d.role_arn("plain"), d.saml_arn("Okta"))],
                    )
                } else {
                    (n.clone(), v.clone())
                }
            })
            .collect(),
        ..tagged.clone()
    };
    refused(
        &d,
        &assuming(&d, "plain", &idp.response(&plain), ""),
        "AccessDenied",
        "Not authorized to perform sts:TagSession",
    );
    let sourced = for_role(&d, "plain").with("SourceIdentity", &["alice"]);
    refused(
        &d,
        &assuming(&d, "plain", &idp.response(&sourced), ""),
        "AccessDenied",
        "Not authorized to perform sts:SetSourceIdentity",
    );

    // Session policies narrow it.
    let answer = ok(
        d.saml(&body(
            &good,
            &format!(
                "&Policy={}",
                enc(
                    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#
                )
            ),
        )),
        "policy",
    );
    assert!(answer.contains("<PackedPolicySize>"), "{answer}");

    // Responses AWS wouldn't take.
    for (saml, code_, words) in [
        (
            Saml {
                signed: Signed::Neither,
                ..good.clone()
            },
            "InvalidIdentityToken",
            "Response signature invalid",
        ),
        (
            Saml {
                expires_in: -600,
                ..good.clone()
            },
            "ExpiredTokenException",
            "has passed",
        ),
        (
            Saml {
                status: "urn:oasis:names:tc:SAML:2.0:status:Requester".into(),
                ..good.clone()
            },
            "IDPRejectedClaim",
            "didn&apos;t sign the user in",
        ),
        (
            Saml {
                subject: String::new(),
                ..good.clone()
            },
            "AccessDenied",
            "NameID",
        ),
    ] {
        refused(&d, &body(&saml, ""), code_, words);
    }
    // Parameters.
    let base = body(&good, "");
    for (remove, missing) in [
        ("RoleArn", "roleArn"),
        ("PrincipalArn", "principalArn"),
        ("SAMLAssertion", "sAMLAssertion"),
    ] {
        let without: String = base
            .split('&')
            .filter(|p| !p.starts_with(&format!("{remove}=")))
            .collect::<Vec<_>>()
            .join("&");
        refused(
            &d,
            &without,
            "ValidationError",
            &format!("Value null at &apos;{missing}&apos;"),
        );
    }
    refused(
        &d,
        &format!(
            "Action=AssumeRoleWithSAML&RoleArn={}&PrincipalArn={}&SAMLAssertion=abc",
            enc(&d.role_arn("r")),
            enc(&d.saml_arn("Okta"))
        ),
        "ValidationError",
        "Member must have length between 4 and 100000",
    );
    refused(
        &d,
        &body(&good, "").replace("SAMLAssertion=", "SAMLAssertion=%21%21%21%21"),
        "InvalidIdentityToken",
        "isn&apos;t base64",
    );
    let answer = ok(d.saml(&body(&good, "")), "again");
    assert_eq!(
        between(&answer, "<Subject>", "</Subject>"),
        "alice@example.com"
    );
}
