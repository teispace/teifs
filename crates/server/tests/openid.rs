//! OpenID Connect providers named in a server's settings (MinIO's `identity_openid`):
//! made when it starts, shown in its configuration, and settings that can't be stop it.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use teifs_client::{Client, Zeroizing};
use teifs_server::ConfiguredOidcProvider;

mod common;

use common::{ACCESS_KEY, SECRET_KEY, start_with};

#[tokio::test]
async fn the_settings_providers_are_made_when_it_starts() {
    let roles = ConfiguredOidcProvider {
        url: "https://sso.example.com/realms/a".into(),
        client_id: "teifs".into(),
        role_policies: vec!["readonly".into()],
        claim_name: None,
        claim_userinfo: true,
    };
    let claims = ConfiguredOidcProvider {
        url: "https://idp.example.com".into(),
        client_id: "app".into(),
        ..ConfiguredOidcProvider::default()
    };
    let wanted = vec![roles, claims];
    let server = start_with(|config| config.openid.clone_from(&wanted)).await;

    let providers = server.iam.oidc_providers().unwrap();
    let mut urls: Vec<&str> = providers.iter().map(|p| p.url.as_str()).collect();
    urls.sort_unstable();
    assert_eq!(
        urls,
        [
            "https://idp.example.com",
            "https://sso.example.com/realms/a"
        ]
    );
    let sso = providers.iter().find(|p| p.url.contains("sso")).unwrap();
    assert_eq!(sso.client_ids, ["teifs"]);
    let mut tags = sso.tags.clone();
    tags.sort();
    assert_eq!(
        tags,
        [
            ("teifs:claim-userinfo".to_owned(), "on".to_owned()),
            ("teifs:role-policy".to_owned(), "readonly".to_owned()),
        ]
    );

    let shown = Client::new(
        &server.endpoint,
        ACCESS_KEY,
        Zeroizing::new(SECRET_KEY.to_owned()),
    )
    .unwrap()
    .config()
    .await
    .unwrap()
    .openid;
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0].url, "https://sso.example.com/realms/a");
    assert_eq!(
        shown[0].role_arn.as_deref(),
        Some(teifs_iam::openid_role_arn("teifs").as_str())
    );
    assert_eq!(shown[0].role_policies, ["readonly"]);
    assert_eq!(shown[0].policy_claim, None);
    assert!(shown[0].claim_userinfo);
    assert_eq!(shown[1].role_arn, None);
    assert_eq!(shown[1].policy_claim.as_deref(), Some("policy"));
    assert!(!shown[1].claim_userinfo);
}

#[tokio::test]
async fn wrong_openid_settings_stop_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let mut config = common::config(dir.path(), keys.path());
    config.openid = vec![ConfiguredOidcProvider {
        url: "ftp://idp.example.com".into(),
        client_id: "app".into(),
        ..ConfiguredOidcProvider::default()
    }];
    let err = Box::pin(teifs_server::Server::bind(config))
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        err.contains("the OpenID Connect providers' settings are wrong"),
        "{err}"
    );
}
