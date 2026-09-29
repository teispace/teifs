//! OpenID Connect providers: their lifecycle, AWS's limits and who may manage them.

use super::{ALLOW_ALL, drive, enc, policy, statement};

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn providers_are_made_changed_and_deleted_as_on_aws() {
    let d = drive().await;
    let root = d.root();
    let url = "https://idp.example.com/realms/Main";
    let arn = d.oidc_arn("idp.example.com/realms/Main");
    let thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1";
    let body = d.ok(
        &root,
        &format!(
            "Action=CreateOpenIDConnectProvider&Url={}&ClientIDList.member.1=app\
             &ClientIDList.member.2=cli&ClientIDList.member.3=app\
             &ThumbprintList.member.1={thumbprint}\
             &ThumbprintList.member.2={}&Tags.member.1.Key=team&Tags.member.1.Value=a\
             &Tags.member.2.Key=Env&Tags.member.2.Value=prod",
            enc(url),
            thumbprint.to_ascii_uppercase()
        ),
    );
    assert!(
        body.contains(&format!(
            "<CreateOpenIDConnectProviderResult><OpenIDConnectProviderArn>{arn}\
             </OpenIDConnectProviderArn><Tags><member><Key>Env</Key><Value>prod</Value>\
             </member><member><Key>team</Key><Value>a</Value></member></Tags>\
             </CreateOpenIDConnectProviderResult>"
        )),
        "{body}"
    );

    let get = format!(
        "Action=GetOpenIDConnectProvider&OpenIDConnectProviderArn={}",
        enc(&arn)
    );
    let body = d.ok(&root, &get);
    assert!(
        body.contains(&format!(
            "<GetOpenIDConnectProviderResult><ThumbprintList><member>{thumbprint}</member>\
             </ThumbprintList><CreateDate>"
        )),
        "the same thumbprint in capitals is the same one: {body}"
    );
    assert!(
        body.contains(
            "<ClientIDList><member>app</member><member>cli</member></ClientIDList>\
             <Url>idp.example.com/realms/Main</Url><Tags>"
        ),
        "{body}"
    );
    // The ARN resolves without case.
    d.ok(
        &root,
        &format!(
            "Action=GetOpenIDConnectProvider&OpenIDConnectProviderArn={}",
            enc(&arn.replace("idp.example.com/realms/Main", "IDP.example.com/realms/main"))
        ),
    );

    let body = d.ok(&root, "Action=ListOpenIDConnectProviders");
    assert!(
        body.contains(&format!(
            "<OpenIDConnectProviderList><member><Arn>{arn}</Arn></member>\
             </OpenIDConnectProviderList>"
        )),
        "{body}"
    );

    let on = format!("OpenIDConnectProviderArn={}", enc(&arn));
    // Adding an audience it has and removing one it hasn't change nothing.
    for body in [
        format!("Action=AddClientIDToOpenIDConnectProvider&{on}&ClientID=app"),
        format!("Action=AddClientIDToOpenIDConnectProvider&{on}&ClientID=web"),
        format!("Action=RemoveClientIDFromOpenIDConnectProvider&{on}&ClientID=cli"),
        format!("Action=RemoveClientIDFromOpenIDConnectProvider&{on}&ClientID=none"),
        format!("Action=UpdateOpenIDConnectProviderThumbprint&{on}"),
        format!("Action=UntagOpenIDConnectProvider&{on}&TagKeys.member.1=ENV"),
        format!(
            "Action=TagOpenIDConnectProvider&{on}&Tags.member.1.Key=TEAM\
             &Tags.member.1.Value=b"
        ),
    ] {
        d.ok(&root, &body);
    }
    let provider = d.iam.oidc_provider(&arn).unwrap();
    assert_eq!(provider.client_ids, ["app", "web"]);
    assert!(provider.thumbprints.is_empty());
    assert_eq!(provider.tags, [("TEAM".to_owned(), "b".to_owned())]);
    assert_eq!(provider.url, url);

    d.iam
        .tag_oidc_provider(&arn, &[("z".into(), "1".into())])
        .unwrap();
    let body = d.ok(
        &root,
        &format!("Action=ListOpenIDConnectProviderTags&{on}&MaxItems=1"),
    );
    assert!(
        body.contains(
            "<Tags><member><Key>TEAM</Key><Value>b</Value></member></Tags>\
             <IsTruncated>true</IsTruncated><Marker>"
        ),
        "{body}"
    );

    // Deleting is idempotent, as on AWS.
    for _ in 0..2 {
        d.ok(&root, &format!("Action=DeleteOpenIDConnectProvider&{on}"));
    }
    let reply = d.call(&root, &get);
    assert_eq!(reply.status, 404, "{}", reply.body);
    assert!(reply.body.contains(&format!(
        "<Code>NoSuchEntity</Code><Message>OpenIDConnect Provider not found for arn {arn}"
    )));
    for body in [
        format!("Action=AddClientIDToOpenIDConnectProvider&{on}&ClientID=app"),
        format!("Action=UpdateOpenIDConnectProviderThumbprint&{on}"),
        format!("Action=TagOpenIDConnectProvider&{on}&Tags.member.1.Key=k&Tags.member.1.Value=v"),
        format!("Action=ListOpenIDConnectProviderTags&{on}"),
    ] {
        assert_eq!(d.code(&root, &body), "NoSuchEntity", "{body}");
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn providers_keep_to_aws_limits() {
    let d = drive().await;
    let root = d.root();
    let create = |url: &str, rest: &str| {
        d.code(
            &root,
            &format!("Action=CreateOpenIDConnectProvider&Url={}{rest}", enc(url)),
        )
    };
    for url in [
        "idp.example.com",
        "http://idp.example.com",
        "https://idp.example.com?a=1",
        "https://u@idp.example.com",
    ] {
        assert_eq!(create(url, ""), "InvalidInput", "{url}");
    }
    assert_eq!(
        d.code(&root, "Action=CreateOpenIDConnectProvider"),
        "ValidationError"
    );
    let url = "https://idp.example.com";
    let thumbprints: String = (1..=6)
        .map(|n| format!("&ThumbprintList.member.{n}={}", n.to_string().repeat(40)))
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(create(url, &thumbprints), "LimitExceeded");
    assert_eq!(
        create(url, &format!("&ThumbprintList.member.1={}", "g".repeat(40))),
        "InvalidInput"
    );
    let client_ids: String = (1..=101)
        .map(|n| format!("&ClientIDList.member.{n}=app{n}"))
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(create(url, &client_ids), "LimitExceeded");
    assert_eq!(
        create(url, &format!("&ClientIDList.member.1={}", "x".repeat(256))),
        "InvalidInput"
    );

    let provider = d.oidc(url);
    assert_eq!(create("https://IDP.example.com", ""), "EntityAlreadyExists");
    // The same URL over http would share the ARN.
    d.oidc("http://localhost:5556/dex");
    assert_eq!(
        create("https://localhost:5556/dex", ""),
        "EntityAlreadyExists"
    );

    let on = format!("OpenIDConnectProviderArn={}", enc(&provider.arn));
    assert_eq!(
        d.code(
            &root,
            &format!(
                "Action=AddClientIDToOpenIDConnectProvider&{on}&ClientID={}",
                "x".repeat(256)
            )
        ),
        "ValidationError"
    );
    for n in 2..=100 {
        d.iam
            .add_client_id(&provider.arn, &format!("app{n}"))
            .unwrap();
    }
    assert_eq!(
        d.code(
            &root,
            &format!("Action=AddClientIDToOpenIDConnectProvider&{on}&ClientID=one-more")
        ),
        "LimitExceeded"
    );
    d.ok(
        &root,
        &format!("Action=AddClientIDToOpenIDConnectProvider&{on}&ClientID=app"),
    );

    for (arn, code) in [
        ("arn:aws:iam::1:x", "ValidationError"),
        ("arn:aws:iam::123456789012:role/r", "InvalidInput"),
        ("arn:aws:iam::123456789012:oidc-provider/", "InvalidInput"),
        (
            "arn:aws:iam::123456789012:oidc-provider/idp.example.com",
            "NoSuchEntity",
        ),
    ] {
        assert_eq!(
            d.code(
                &root,
                &format!(
                    "Action=GetOpenIDConnectProvider&OpenIDConnectProviderArn={}",
                    enc(arn)
                )
            ),
            code,
            "{arn}"
        );
    }
    assert_eq!(
        d.code(
            &root,
            "Action=DeleteOpenIDConnectProvider&OpenIDConnectProviderArn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fr"
        ),
        "InvalidInput",
        "only a provider that doesn't exist is already deleted"
    );

    for n in 2..100 {
        d.oidc(&format!("https://idp{n}.example.com"));
    }
    assert_eq!(d.iam.oidc_providers().unwrap().len(), 100);
    assert_eq!(create("https://one-more.example.com", ""), "LimitExceeded");
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn providers_are_authorized_by_their_arn_and_tags() {
    let d = drive().await;
    let tagged = d
        .iam
        .create_oidc_provider(&crate::NewOidcProvider {
            url: "https://tagged.example.com",
            tags: &[("team".into(), "a".into())],
            ..crate::NewOidcProvider::default()
        })
        .unwrap();
    let other = d.oidc("https://other.example.com");
    let caller = d.identity(&d.user(
        "caller",
        &policy(&[
            statement(
                "Allow",
                "iam:*OpenIDConnectProvider*",
                "*",
                r#"{"StringEquals":{"aws:ResourceTag/team":"a"}}"#,
            ),
            statement("Allow", "iam:ListOpenIDConnectProviders", "*", ""),
            statement(
                "Allow",
                "iam:CreateOpenIDConnectProvider",
                "arn:aws:iam::*:oidc-provider/new.example.com",
                "",
            ),
            statement(
                "Deny",
                "iam:TagOpenIDConnectProvider",
                "*",
                r#"{"ForAnyValue:StringEquals":{"aws:TagKeys":"owner"}}"#,
            ),
        ]),
    ));
    let get = |arn: &str| {
        format!(
            "Action=GetOpenIDConnectProvider&OpenIDConnectProviderArn={}",
            enc(arn)
        )
    };
    d.ok(&caller, &get(&tagged.arn));
    d.ok(
        &caller,
        &get(&tagged
            .arn
            .replace("tagged.example.com", "TAGGED.example.com")),
    );
    assert_eq!(d.code(&caller, &get(&other.arn)), "AccessDenied");
    d.ok(&caller, "Action=ListOpenIDConnectProviders");

    let create = |url: &str, tags: &str| {
        format!("Action=CreateOpenIDConnectProvider&Url={}{tags}", enc(url))
    };
    assert_eq!(
        d.code(&caller, &create("https://elsewhere.example.com", "")),
        "AccessDenied"
    );
    // Tags need TagOpenIDConnectProvider too, which this caller has only on tagged ones.
    assert_eq!(
        d.code(
            &caller,
            &create(
                "https://new.example.com",
                "&Tags.member.1.Key=team&Tags.member.1.Value=a"
            )
        ),
        "AccessDenied"
    );
    d.ok(&caller, &create("https://new.example.com", ""));

    let on = format!("OpenIDConnectProviderArn={}", enc(&tagged.arn));
    assert_eq!(
        d.code(
            &caller,
            &format!(
                "Action=TagOpenIDConnectProvider&{on}&Tags.member.1.Key=owner\
                 &Tags.member.1.Value=x"
            )
        ),
        "AccessDenied"
    );
    // Untagging `team` takes away the caller's access to it.
    d.ok(
        &caller,
        &format!("Action=UntagOpenIDConnectProvider&{on}&TagKeys.member.1=team"),
    );
    assert_eq!(d.code(&caller, &get(&tagged.arn)), "AccessDenied");

    let admin = d.identity(&d.user("admin", ALLOW_ALL));
    d.ok(&admin, &get(&other.arn));

    // A name in another case is still the provider's own ARN, which policies match
    // with case; and untagging tells policies which keys go.
    let limited = d.identity(&d.user(
        "limited",
        &policy(&[
            statement("Allow", "iam:*", "*", ""),
            statement("Deny", "iam:GetOpenIDConnectProvider", &other.arn, ""),
            statement(
                "Deny",
                "iam:UntagOpenIDConnectProvider",
                "*",
                r#"{"ForAnyValue:StringEquals":{"aws:TagKeys":"owner"}}"#,
            ),
        ]),
    ));
    assert_eq!(
        d.code(
            &limited,
            &get(&other.arn.replace("other.example.com", "OTHER.example.com"))
        ),
        "AccessDenied"
    );
    let on = format!("OpenIDConnectProviderArn={}", enc(&other.arn));
    assert_eq!(
        d.code(
            &limited,
            &format!("Action=UntagOpenIDConnectProvider&{on}&TagKeys.member.1=owner")
        ),
        "AccessDenied"
    );
    d.ok(
        &limited,
        &format!("Action=UntagOpenIDConnectProvider&{on}&TagKeys.member.1=team"),
    );
}
