//! `MinIO`'s identity provider configurations (`mc admin idp ldap|openid add|update|
//! remove|info|list`) on the drive's `.teifs/config.kv`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use serde_json::{Value, json};
use teifs_crypto::madmin;

use common::{ACCESS_KEY, SECRET_KEY, Server, start};
use signing::signed_response;

const ADMIN: &str = "/minio/admin/v3/idp-config/";
const LDAP: &str = "server_addr=ldap.example.com:636 lookup_bind_dn=\"cn=admin, dc=example\" \
                    lookup_bind_password=pw-1";
const DEX: &str = "config_url=https://dex.example.com/.well-known/openid-configuration \
                   client_id=teifs client_secret=dex-secret-1 role_policy=readonly";

/// A call as madmin makes it: `body` encrypted for the root key's secret and sent as an
/// opaque stream, and the answer decrypted when it succeeded with one.
async fn call(server: &Server, method: &str, path: &str, body: Option<&str>) -> (u16, Value) {
    let body = body.map_or_else(Vec::new, |b| madmin::encrypt(SECRET_KEY, b.as_bytes()));
    let headers = [("content-type", "application/octet-stream")];
    let response = signed_response(
        server,
        (ACCESS_KEY, SECRET_KEY),
        method,
        &format!("{ADMIN}{path}"),
        &headers,
        &body,
    )
    .await;
    let status = response.status().as_u16();
    assert!(!response.headers().contains_key("x-minio-config-applied"));
    let bytes = response.bytes().await.unwrap();
    if bytes.is_empty() {
        return (status, Value::Null);
    }
    if (200..300).contains(&status) {
        let plain = madmin::decrypt(SECRET_KEY, &bytes).unwrap();
        return (status, serde_json::from_slice(&plain).unwrap());
    }
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn stored(server: &Server) -> String {
    std::fs::read_to_string(server.dir.path().join(".teifs/config.kv")).unwrap_or_default()
}

/// An info answer's values by key.
fn values(info: &Value) -> Vec<(String, String)> {
    info["info"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            assert_eq!(i["isEnv"], false);
            (
                i["key"].as_str().unwrap().to_owned(),
                i["value"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[tokio::test]
async fn the_ldap_configuration_is_added_read_changed_and_removed() {
    let server = start().await;
    let (status, list) = call(&server, "GET", "ldap", None).await;
    assert_eq!(status, 200);
    assert_eq!(
        list,
        json!([{"type": "ldap", "name": "_", "enabled": false}])
    );
    // Nothing is set: info is empty, and there's nothing to update.
    let (status, info) = call(&server, "GET", "ldap/_", None).await;
    assert_eq!((status, &info["info"]), (200, &json!([])));
    let (status, err) = call(&server, "POST", "ldap/_", Some(LDAP)).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioAdminConfigIDPCfgNameDoesNotExist"))
    );

    let (status, _) = call(&server, "PUT", "ldap/_", Some(LDAP)).await;
    assert_eq!(status, 200);
    assert!(stored(&server).contains("identity_ldap "));
    let (_, info) = call(&server, "GET", "ldap/_", None).await;
    assert_eq!(
        (&info["type"], &info["name"]),
        (&json!("ldap"), &json!("_"))
    );
    let values = values(&info);
    assert!(values.contains(&("server_addr".into(), "ldap.example.com:636".into())));
    assert!(values.contains(&("lookup_bind_dn".into(), "cn=admin, dc=example".into())));
    assert!(
        values.iter().all(|(key, _)| key != "lookup_bind_password"),
        "secrets stay out"
    );
    let keys: Vec<&str> = values.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.is_sorted(), "{keys:?}");
    let (_, list) = call(&server, "GET", "ldap", None).await;
    assert_eq!(list[0]["enabled"], true);

    // A second add is refused; an update changes what it names and keeps the rest.
    let (status, err) = call(&server, "PUT", "ldap/_", Some(LDAP)).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioAdminConfigIDPCfgNameAlreadyExists"))
    );
    let more = "user_dn_search_base_dn=dc=example user_dn_search_filter=(uid=%s)";
    assert_eq!(call(&server, "POST", "ldap/_", Some(more)).await.0, 200);
    let (_, info) = call(&server, "GET", "ldap/_", None).await;
    let values = self::values(&info);
    assert!(values.contains(&("server_addr".into(), "ldap.example.com:636".into())));
    assert!(values.contains(&("user_dn_search_filter".into(), "(uid=%s)".into())));
    // Taken by `mc admin config` too.
    let history = std::fs::read_dir(server.dir.path().join(".teifs/config-history"))
        .map_or(0, Iterator::count);
    assert_eq!(history, 2);

    // LDAP has one configuration.
    for (method, path) in [("PUT", "ldap/other"), ("POST", "ldap/other")] {
        let (status, err) = call(&server, method, path, Some(LDAP)).await;
        assert_eq!(
            (status, err["Code"].as_str()),
            (400, Some("XMinioAdminConfigLDAPNonDefaultConfigName")),
            "{method}"
        );
    }
    for (method, path) in [("GET", "ldap/other"), ("DELETE", "ldap/other")] {
        let (status, err) = call(&server, method, path, None).await;
        assert_eq!(
            (status, err["Code"].as_str()),
            (400, Some("XMinioAdminNoSuchConfigTarget")),
            "{method}"
        );
    }

    assert_eq!(call(&server, "DELETE", "ldap/_", None).await.0, 200);
    assert!(!stored(&server).contains("identity_ldap"));
    let (_, info) = call(&server, "GET", "ldap/_", None).await;
    assert_eq!(info["info"], json!([]));
}

#[tokio::test]
async fn openid_configurations_are_named() {
    let server = start().await;
    assert_eq!(call(&server, "PUT", "openid/dex", Some(DEX)).await.0, 200);
    assert!(stored(&server).contains("identity_openid:dex "));
    let (status, list) = call(&server, "GET", "openid", None).await;
    assert_eq!(status, 200);
    let role_arn = teifs_iam::openid_role_arn("teifs");
    assert_eq!(
        list,
        json!([
            {"type": "openid", "name": "_", "enabled": false},
            {"type": "openid", "name": "dex", "enabled": true, "roleARN": role_arn},
        ])
    );
    let (_, info) = call(&server, "GET", "openid/dex", None).await;
    let role = info["info"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["key"] == "roleARN")
        .unwrap();
    assert_eq!(
        role,
        &json!({"key": "roleARN", "value": role_arn, "isCfg": false, "isEnv": false})
    );
    assert!(
        info["info"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["key"] != "client_secret")
    );
    // Off, it has no role ARN.
    assert_eq!(
        call(&server, "POST", "openid/dex", Some("enable=off"))
            .await
            .0,
        200
    );
    let (_, list) = call(&server, "GET", "openid", None).await;
    assert_eq!(
        list[1],
        json!({"type": "openid", "name": "dex", "enabled": false})
    );

    let (status, err) = call(&server, "GET", "openid/keycloak", None).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioAdminNoSuchConfigTarget"))
    );
    let (status, err) = call(&server, "POST", "openid/keycloak", Some(DEX)).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioAdminConfigIDPCfgNameDoesNotExist"))
    );
    assert_eq!(call(&server, "DELETE", "openid/dex", None).await.0, 200);
    let (_, list) = call(&server, "GET", "openid", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn bad_calls_are_refused_as_minio_refuses_them() {
    let server = start().await;
    let (status, err) = call(&server, "GET", "saml", None).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioAdminConfigInvalidIDPType"))
    );
    // A configuration the next start couldn't use isn't kept.
    let (status, err) = call(&server, "PUT", "openid/dex", Some("client_id=teifs")).await;
    assert_eq!(status, 400, "{err}");
    assert!(!stored(&server).contains("identity_openid"));
    let (status, err) = call(&server, "PUT", "openid/dex", Some("no_such_key=1")).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioConfigError"))
    );
    // madmin sends the body as an opaque stream; anything else is refused.
    let body = madmin::encrypt(SECRET_KEY, DEX.as_bytes());
    let response = signed_response(
        &server,
        (ACCESS_KEY, SECRET_KEY),
        "PUT",
        &format!("{ADMIN}openid/dex"),
        &[("content-type", "application/x-www-form-urlencoded")],
        &body,
    )
    .await;
    assert_eq!(response.status(), 400);
    // A body not encrypted with the caller's secret.
    let response = signed_response(
        &server,
        (ACCESS_KEY, SECRET_KEY),
        "PUT",
        &format!("{ADMIN}openid/dex"),
        &[("content-type", "application/octet-stream")],
        DEX.as_bytes(),
    )
    .await;
    assert_eq!(response.status(), 400);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["Code"], "XMinioAdminConfigBadJSON");
    // v4 paths answer as v3's.
    let response = signed_response(
        &server,
        (ACCESS_KEY, SECRET_KEY),
        "GET",
        "/minio/admin/v4/idp-config/ldap",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status(), 200);
}
