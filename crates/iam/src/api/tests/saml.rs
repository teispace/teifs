//! SAML providers: their lifecycle, AWS's rules for metadata and private keys, who may
//! manage them, and moving them between drives.

use super::{drive, enc, policy, statement, trust};
use crate::saml::{metadata::tests as metadata, private_key::tests::new_pem};

/// A metadata document with a new RSA signing certificate.
pub(super) fn document(entity_id: &str) -> String {
    let (der, _) = metadata::certificate(true);
    metadata::document(entity_id, &[&der])
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn providers_are_made_changed_and_deleted_as_on_aws() {
    let d = drive().await;
    let root = d.root();
    let doc = document("https://idp.example.com/saml");
    let arn = format!("arn:aws:iam::{}:saml-provider/Okta", d.account);
    let body = d.ok(
        &root,
        &format!(
            "Action=CreateSAMLProvider&Name=Okta&SAMLMetadataDocument={}\
             &Tags.member.1.Key=team&Tags.member.1.Value=a",
            enc(&doc)
        ),
    );
    assert!(
        body.contains(&format!(
            "<CreateSAMLProviderResult><SAMLProviderArn>{arn}</SAMLProviderArn><Tags>\
             <member><Key>team</Key><Value>a</Value></member></Tags></CreateSAMLProviderResult>"
        )),
        "{body}"
    );

    let on = format!("SAMLProviderArn={}", enc(&arn));
    let body = d.ok(&root, &format!("Action=GetSAMLProvider&{on}"));
    let uuid = super::between(&body, "<SAMLProviderUUID>", "</SAMLProviderUUID>");
    assert!(uuid.len() == 22 && uuid.starts_with("SAML"), "{body}");
    assert!(
        body.contains("entityID=&quot;https://idp.example.com/saml&quot;"),
        "{body}"
    );
    let created = super::between(&body, "<CreateDate>", "</CreateDate>");
    let until = super::between(&body, "<ValidUntil>", "</ValidUntil>");
    assert_eq!(
        until[4..],
        created[4..],
        "valid for a hundred years: {body}"
    );
    assert_eq!(
        until[..4].parse::<u32>().unwrap(),
        created[..4].parse::<u32>().unwrap() + 100
    );
    assert!(!body.contains("AssertionEncryptionMode") && !body.contains("PrivateKeyList"));
    // The ARN resolves without case.
    d.ok(
        &root,
        &format!(
            "Action=GetSAMLProvider&SAMLProviderArn={}",
            enc(&arn.replace("Okta", "OKTA"))
        ),
    );

    let body = d.ok(&root, "Action=ListSAMLProviders");
    assert!(
        body.contains(&format!(
            "<SAMLProviderList><member><Arn>{arn}</Arn><ValidUntil>{until}</ValidUntil>\
             <CreateDate>{created}</CreateDate></member></SAMLProviderList>"
        )),
        "{body}"
    );

    // Private keys: AWS's rules for adding, removing and requiring them.
    let update = |rest: &str| format!("Action=UpdateSAMLProvider&{on}{rest}");
    let key = |pem: &str| format!("&AddPrivateKey={}", enc(pem));
    let first = new_pem();
    let refused = [
        (update(""), "InvalidInput", "No updates are defined"),
        (
            update("&AssertionEncryptionMode=Required"),
            "InvalidInput",
            "because no private key is provided",
        ),
        (
            update(&format!(
                "{}&RemovePrivateKey={}",
                key(&first),
                "SAML".repeat(6)
            )),
            "InvalidInput",
            "Unable to add and remove private keys in the same request",
        ),
        (
            update(&format!("&RemovePrivateKey={}", "SAML".repeat(6))),
            "InvalidInput",
            "the Key ID does not match a private key",
        ),
        (
            update("&AssertionEncryptionMode=Sometimes"),
            "ValidationError",
            "AssertionEncryptionMode",
        ),
        (
            update("&AddPrivateKey=nope"),
            "InvalidInput",
            "Invalid private key: Key format is not recognized.",
        ),
    ];
    for (request, code, words) in refused {
        let reply = d.call(&root, &request);
        assert_eq!(super::code(&reply, &request), code, "{}", reply.body);
        assert!(reply.body.contains(words), "{}", reply.body);
    }
    let body = d.ok(
        &root,
        &update(&format!("{}&AssertionEncryptionMode=Required", key(&first))),
    );
    assert!(
        body.contains(&format!("<SAMLProviderArn>{arn}</SAMLProviderArn>")),
        "{body}"
    );
    d.ok(&root, &update(&key(&new_pem())));
    let reply = d.call(&root, &update(&key(&new_pem())));
    assert_eq!(super::code(&reply, "a third key"), "LimitExceeded");
    assert!(
        reply.body.contains("Private key limit of 2 is reached."),
        "{}",
        reply.body
    );
    let body = d.ok(&root, &format!("Action=GetSAMLProvider&{on}"));
    assert!(
        body.contains("<AssertionEncryptionMode>Required</AssertionEncryptionMode>"),
        "{body}"
    );
    let list = super::between(&body, "<PrivateKeyList>", "</PrivateKeyList>");
    let ids: Vec<&str> = list
        .split("<KeyId>")
        .skip(1)
        .map(|m| m.split_once("</KeyId>").unwrap().0)
        .collect();
    assert_eq!(ids.len(), 2, "{body}");
    assert!(list.contains("<Timestamp>"), "{body}");
    assert!(
        !body.contains("PRIVATE KEY"),
        "the keys are never shown: {body}"
    );
    d.ok(&root, &update(&format!("&RemovePrivateKey={}", ids[0])));
    let reply = d.call(&root, &update(&format!("&RemovePrivateKey={}", ids[1])));
    assert_eq!(super::code(&reply, "the last key"), "InvalidInput");
    assert!(
        reply.body.contains("Failed to remove private key."),
        "{}",
        reply.body
    );
    d.ok(&root, &update("&AssertionEncryptionMode=Allowed"));
    d.ok(&root, &update(&format!("&RemovePrivateKey={}", ids[1])));
    let body = d.ok(&root, &format!("Action=GetSAMLProvider&{on}"));
    assert!(!body.contains("PrivateKeyList"), "{body}");

    // A new metadata document, read like the first.
    let other = document("https://other.example.com/saml");
    d.ok(
        &root,
        &update(&format!("&SAMLMetadataDocument={}", enc(&other))),
    );
    assert_eq!(
        d.iam.saml_provider(&arn).unwrap().issuer,
        "https://other.example.com/saml"
    );

    // Tags.
    d.ok(
        &root,
        &format!("Action=TagSAMLProvider&{on}&Tags.member.1.Key=Env&Tags.member.1.Value=prod"),
    );
    d.ok(
        &root,
        &format!("Action=UntagSAMLProvider&{on}&TagKeys.member.1=TEAM"),
    );
    let body = d.ok(&root, &format!("Action=ListSAMLProviderTags&{on}"));
    assert!(
        body.contains("<Tags><member><Key>Env</Key><Value>prod</Value></member></Tags>"),
        "{body}"
    );

    // A trust policy may name it, and no SAML provider that doesn't exist.
    let missing = format!("arn:aws:iam::{}:saml-provider/Missing", d.account);
    for (provider, code) in [(&arn, None), (&missing, Some("MalformedPolicyDocument"))] {
        let request = format!(
            "Action=CreateRole&RoleName=r{}&AssumeRolePolicyDocument={}",
            code.is_some(),
            enc(&trust(&format!(r#"{{"Federated":"{provider}"}}"#)))
                .replace("sts%3AAssumeRole%22", "sts%3AAssumeRoleWithSAML%22")
        );
        match code {
            None => {
                d.ok(&root, &request);
            }
            Some(code) => assert_eq!(d.code(&root, &request), code),
        }
    }

    assert_eq!(
        d.reopened().await.saml_provider(&arn).unwrap(),
        d.iam.saml_provider(&arn).unwrap(),
        "what was saved"
    );
    d.ok(&root, &format!("Action=DeleteSAMLProvider&{on}"));
    for action in ["GetSAMLProvider", "DeleteSAMLProvider"] {
        let reply = d.call(&root, &format!("Action={action}&{on}"));
        assert_eq!(super::code(&reply, action), "NoSuchEntity");
        assert!(
            reply.body.contains("Manifest not found for arn"),
            "{}",
            reply.body
        );
    }
}

#[tokio::test]
async fn providers_keep_to_aws_limits() {
    let d = drive().await;
    let root = d.root();
    let doc = document("https://idp.example.com/saml");
    let create = |name: &str, rest: &str| {
        d.call(
            &root,
            &format!(
                "Action=CreateSAMLProvider&Name={name}&SAMLMetadataDocument={}{rest}",
                enc(&doc)
            ),
        )
    };
    let secret = new_pem();
    let refused = [
        (create("has space", ""), "InvalidInput", "must be 1 to 128"),
        (create("a%2Fb", ""), "InvalidInput", "must be 1 to 128"),
        (
            create(&"n".repeat(129), ""),
            "ValidationError",
            "less than or equal to 128",
        ),
        (
            create("p", "&AssertionEncryptionMode=Required"),
            "InvalidInput",
            "because no private key is provided",
        ),
        (
            create("p", &format!("&AddPrivateKey={}", enc(&secret[..200]))),
            "InvalidInput",
            "Invalid private key",
        ),
        (
            create("p", &format!("&AddPrivateKey={}", "k".repeat(16_385))),
            "ValidationError",
            "less than or equal to 16384",
        ),
        (
            d.call(
                &root,
                "Action=CreateSAMLProvider&Name=p&SAMLMetadataDocument=%3Cshort%2F%3E",
            ),
            "ValidationError",
            "greater than or equal to 1000",
        ),
        (
            d.call(
                &root,
                &format!(
                    "Action=CreateSAMLProvider&Name=p&SAMLMetadataDocument={}",
                    enc(&format!("<a>{}</a>", "x".repeat(1000)))
                ),
            ),
            "InvalidInput",
            "Could not parse metadata",
        ),
    ];
    for (reply, code, words) in refused {
        assert_eq!(super::code(&reply, words), code, "{}", reply.body);
        assert!(reply.body.contains(words), "{}", reply.body);
        // Neither a key nor a document is ever repeated back.
        assert!(
            !reply.body.contains("kkkk") && !reply.body.contains("PRIVATE"),
            "{}",
            reply.body
        );
        assert!(!reply.body.contains("xxxx"), "{}", reply.body);
    }

    let made = create(
        "Okta",
        &format!(
            "&AssertionEncryptionMode=Required&AddPrivateKey={}",
            enc(&secret)
        ),
    );
    assert_eq!(made.status, 200, "{}", made.body);
    let again = create("OKTA", "");
    assert_eq!(super::code(&again, "the same name"), "EntityAlreadyExists");
    for n in 1..100 {
        d.iam
            .create_saml_provider(&crate::NewSamlProvider {
                name: &format!("p{n}"),
                metadata: &doc,
                ..crate::NewSamlProvider::default()
            })
            .unwrap();
    }
    let over = create("one-more", "");
    assert_eq!(super::code(&over, "the 101st"), "LimitExceeded");
    assert!(
        over.body.contains("SAMLProvidersPerAccount: 100"),
        "{}",
        over.body
    );
}

#[tokio::test]
async fn who_may_manage_providers_is_up_to_policies() {
    let d = drive().await;
    let root = d.root();
    let doc = document("https://idp.example.com/saml");
    for name in ["Mine", "Theirs"] {
        d.ok(
            &root,
            &format!(
                "Action=CreateSAMLProvider&Name={name}&SAMLMetadataDocument={}\
                 &Tags.member.1.Key=owner&Tags.member.1.Value={name}",
                enc(&doc)
            ),
        );
    }
    let key = d.user(
        "alice",
        &policy(&[
            statement(
                "Allow",
                "iam:GetSAMLProvider",
                "*",
                r#"{"StringEquals":{"aws:ResourceTag/owner":"Mine"}}"#,
            ),
            statement("Allow", "iam:ListSAMLProviders", "*", ""),
            statement("Allow", "iam:CreateSAMLProvider", "*", ""),
        ]),
    );
    let alice = d.identity(&key);
    let arn = |name: &str| format!("arn:aws:iam::{}:saml-provider/{name}", d.account);
    d.ok(&alice, "Action=ListSAMLProviders");
    d.ok(
        &alice,
        &format!(
            "Action=GetSAMLProvider&SAMLProviderArn={}",
            enc(&arn("Mine"))
        ),
    );
    for request in [
        format!(
            "Action=GetSAMLProvider&SAMLProviderArn={}",
            enc(&arn("Theirs"))
        ),
        format!(
            "Action=DeleteSAMLProvider&SAMLProviderArn={}",
            enc(&arn("Mine"))
        ),
        format!(
            "Action=CreateSAMLProvider&Name=New&SAMLMetadataDocument={}\
             &Tags.member.1.Key=owner&Tags.member.1.Value=New",
            enc(&doc)
        ),
    ] {
        assert_eq!(d.code(&alice, &request), "AccessDenied", "{request}");
    }
    // Without tags, creating is all it takes.
    d.ok(
        &alice,
        &format!(
            "Action=CreateSAMLProvider&Name=New&SAMLMetadataDocument={}",
            enc(&doc)
        ),
    );
}

#[tokio::test]
async fn providers_move_with_their_keys_only_in_an_export_with_secrets() {
    let d = drive().await;
    let doc = document("https://idp.example.com/saml");
    let made = d
        .iam
        .create_saml_provider(&crate::NewSamlProvider {
            name: "Okta",
            metadata: &doc,
            encryption: Some("Required"),
            private_key: Some(&new_pem()),
            tags: &[("team".into(), "a".into())],
        })
        .unwrap();
    d.iam
        .update_saml_provider(
            &made.arn,
            &crate::SamlProviderUpdate {
                add_key: Some(&new_pem()),
                ..crate::SamlProviderUpdate::default()
            },
        )
        .unwrap();
    d.iam
        .create_saml_provider(&crate::NewSamlProvider {
            name: "Plain",
            metadata: &doc,
            ..crate::NewSamlProvider::default()
        })
        .unwrap();

    let export = d.iam.export(true);
    assert_eq!(export.saml_providers.len(), 2);
    assert_eq!(export.saml_providers[0].private_keys.len(), 2);
    assert!(!format!("{export:?}").contains("PRIVATE KEY"));
    let other = drive().await;
    let report = other.iam.import(&export, false).unwrap();
    assert_eq!(report.saml_providers, 2);
    let copy = other
        .iam
        .saml_provider(&made.arn.replace(&d.account, &other.account))
        .unwrap();
    assert_eq!(copy.encryption, Some("Required"));
    assert_eq!(copy.keys.len(), 2);
    assert_eq!(copy.metadata, doc);
    assert_eq!(copy.tags, [("team".to_owned(), "a".to_owned())]);
    // The keys are the same keys: what they decrypt is what the originals do.
    assert_eq!(
        other.iam.export(true).saml_providers[0].private_keys,
        export.saml_providers[0].private_keys
    );

    // Without secrets there are no keys, and a provider that requires them can't be made.
    let bare = d.iam.export(false);
    assert!(
        bare.saml_providers
            .iter()
            .all(|p| p.private_keys.is_empty())
    );
    let err = drive().await.iam.import(&bare, false).unwrap_err();
    assert!(err.to_string().contains("export with secrets"), "{err}");
}
