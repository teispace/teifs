//! `MinIO`'s configuration calls (`mc admin config get|set|reset|history|restore|export|
//! import`) on the drive's `.teifs/config.kv`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;
mod signing;

use std::sync::Arc;

use serde_json::Value;
use teifs_crypto::madmin;
use teifs_types::config_kv::ConfigKv;

use common::{ACCESS_KEY, SECRET_KEY, Server, start, start_with};
use signing::signed_response;

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);
const ADMIN: &str = "/minio/admin/v3/";
const LDAP: &str = "identity_ldap server_addr=ldap.example.com:636 lookup_bind_dn=\"cn=admin, \
                    dc=example\" lookup_bind_password=pw-1";

/// What a call answered: its status, whether it said the change was applied, and its
/// body (decrypted when it succeeded with one).
struct Answer {
    status: u16,
    applied: bool,
    text: String,
}

impl Answer {
    fn code(&self) -> String {
        let error: Value = serde_json::from_str(&self.text).unwrap();
        error["Code"].as_str().unwrap().to_owned()
    }
}

/// A call with `body` encrypted for the root key's secret, as madmin sends it.
async fn call(server: &Server, method: &str, path: &str, body: Option<&str>) -> Answer {
    let body = body.map_or_else(Vec::new, |b| madmin::encrypt(SECRET_KEY, b.as_bytes()));
    raw(server, method, path, &body).await
}

async fn raw(server: &Server, method: &str, path: &str, body: &[u8]) -> Answer {
    let response =
        signed_response(server, ROOT, method, &format!("{ADMIN}{path}"), &[], body).await;
    let status = response.status().as_u16();
    let applied = response.headers().contains_key("x-minio-config-applied");
    let bytes = response.bytes().await.unwrap();
    let encrypted = (200..300).contains(&status) && !bytes.is_empty() && !path.starts_with("help");
    let text = if encrypted {
        String::from_utf8(madmin::decrypt(SECRET_KEY, &bytes).unwrap().to_vec()).unwrap()
    } else {
        String::from_utf8(bytes.to_vec()).unwrap()
    };
    Answer {
        status,
        applied,
        text,
    }
}

fn stored(server: &Server) -> String {
    std::fs::read_to_string(server.dir.path().join(".teifs/config.kv")).unwrap_or_default()
}

#[tokio::test]
async fn settings_are_set_read_and_reset() {
    let server = start().await;
    let fresh = call(&server, "GET", "get-config-kv?key=identity_ldap", None).await;
    assert_eq!(fresh.status, 200);
    assert!(
        fresh
            .text
            .starts_with("identity_ldap enable= server_addr= "),
        "{}",
        fresh.text
    );

    let set = call(&server, "PUT", "set-config-kv", Some(LDAP)).await;
    assert_eq!((set.status, set.text.as_str()), (200, ""));
    // Applied when the server starts again, as MinIO's settings that aren't dynamic.
    assert!(!set.applied);
    let got = call(&server, "GET", "get-config-kv?key=identity_ldap", None).await;
    assert!(
        got.text.contains("server_addr=ldap.example.com:636 "),
        "{}",
        got.text
    );
    assert!(
        got.text
            .contains("lookup_bind_dn=\"cn=admin, dc=example\" "),
        "{}",
        got.text
    );
    assert!(
        !got.text.contains("pw-1"),
        "secrets aren't read back: {}",
        got.text
    );
    // The drive keeps it, secret and all, for the owner alone.
    assert!(stored(&server).contains("lookup_bind_password=pw-1"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = server.dir.path().join(".teifs/config.kv");
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let reset = call(
        &server,
        "DELETE",
        "del-config-kv",
        Some("identity_ldap lookup_bind_password"),
    )
    .await;
    assert_eq!(reset.status, 200);
    let export = call(&server, "GET", "config", None).await;
    assert!(
        export.text.contains("lookup_bind_password= "),
        "{}",
        export.text
    );
    assert!(
        export.text.contains("# identity_plugin url= "),
        "{}",
        export.text
    );
}

#[tokio::test]
async fn refusals_are_minio_s() {
    let server = start().await;
    for (method, path, body, status, code) in [
        (
            "PUT",
            "set-config-kv",
            Some("storage_class standard=EC:2"),
            400,
            "XMinioConfigError",
        ),
        (
            "PUT",
            "set-config-kv",
            Some("identity_ldap tls_skip_verify=maybe"),
            400,
            "XMinioConfigError",
        ),
        (
            "DELETE",
            "del-config-kv",
            Some("identity_openid:nope"),
            404,
            "XMinioConfigNotFoundError",
        ),
        (
            "GET",
            "get-config-kv?key=identity_openid:nope",
            None,
            400,
            "XMinioConfigError",
        ),
        (
            "GET",
            "get-config-kv?key=storage_class",
            None,
            400,
            "XMinioConfigError",
        ),
    ] {
        let answer = call(&server, method, path, body).await;
        assert_eq!(
            (answer.status, answer.code()),
            (status, code.to_owned()),
            "{path} {body:?}"
        );
    }
    let plain = raw(&server, "PUT", "set-config-kv", LDAP.as_bytes()).await;
    assert_eq!(
        (plain.status, plain.code()),
        (400, "XMinioAdminConfigBadJSON".to_owned())
    );
    let large = raw(&server, "PUT", "set-config-kv", &vec![b'x'; 262_273]).await;
    assert_eq!(
        (large.status, large.code()),
        (400, "XMinioAdminConfigTooLarge".to_owned())
    );
}

#[tokio::test]
async fn changes_can_be_put_back() {
    let server = start().await;
    assert_eq!(
        call(&server, "PUT", "set-config-kv", Some(LDAP))
            .await
            .status,
        200
    );
    let history = call(&server, "GET", "list-config-history-kv?count=10", None).await;
    let entries: Value = serde_json::from_str(&history.text).unwrap();
    assert_eq!(entries.as_array().unwrap().len(), 1, "{entries}");
    assert_eq!(entries[0]["data"], LDAP);
    assert!(entries[0]["createTime"].as_str().unwrap().ends_with('Z'));
    let id = entries[0]["restoreId"].as_str().unwrap().to_owned();
    let all = call(&server, "GET", "list-config-history-kv?count=0", None).await;
    assert_eq!(all.text, history.text, "0 lists every change");

    // Reset, then put the change back: it's set again and leaves the history.
    call(&server, "DELETE", "del-config-kv", Some("identity_ldap")).await;
    assert!(!stored(&server).contains("ldap.example.com"));
    let restored = call(
        &server,
        "PUT",
        &format!("restore-config-history-kv?restoreId={id}"),
        None,
    )
    .await;
    assert_eq!(restored.status, 200, "{}", restored.text);
    assert!(stored(&server).contains("lookup_bind_password=pw-1"));
    let history = call(&server, "GET", "list-config-history-kv?count=0", None).await;
    assert_eq!(history.text, "[]");

    for (method, path, status, code) in [
        (
            "PUT",
            format!("restore-config-history-kv?restoreId={id}"),
            404,
            "XMinioConfigNotFoundError",
        ),
        (
            "DELETE",
            format!("clear-config-history-kv?restoreId={id}"),
            404,
            "XMinioConfigNotFoundError",
        ),
        (
            "DELETE",
            "clear-config-history-kv?restoreId=".to_owned(),
            400,
            "InvalidRequest",
        ),
        (
            "GET",
            "list-config-history-kv?count=many".to_owned(),
            400,
            "XMinioAdminInvalidArgument",
        ),
    ] {
        let answer = call(&server, method, &path, None).await;
        assert_eq!(
            (answer.status, answer.code()),
            (status, code.to_owned()),
            "{path}"
        );
    }

    // An import replaces everything, and is a change too.
    let plugin = "identity_plugin url=https://plugin.example.com role_policy=readonly";
    assert_eq!(
        call(&server, "PUT", "config", Some(plugin)).await.status,
        200
    );
    let config = ConfigKv::parse(&stored(&server)).unwrap();
    assert_eq!(
        config.variables().keys().collect::<Vec<_>>(),
        [
            "MINIO_IDENTITY_PLUGIN_ROLE_POLICY",
            "MINIO_IDENTITY_PLUGIN_URL"
        ]
    );
    call(
        &server,
        "PUT",
        "set-config-kv",
        Some("identity_plugin role_id=r"),
    )
    .await;
    let history = call(&server, "GET", "list-config-history-kv?count=1", None).await;
    let entries: Value = serde_json::from_str(&history.text).unwrap();
    assert_eq!(
        entries[0]["data"], "identity_plugin role_id=r",
        "the newest"
    );
    let cleared = call(
        &server,
        "DELETE",
        "clear-config-history-kv?restoreId=all",
        None,
    )
    .await;
    assert_eq!(cleared.status, 200);
    let history = call(&server, "GET", "list-config-history-kv?count=0", None).await;
    assert_eq!(history.text, "[]");
}

#[tokio::test]
async fn help_needs_no_decryption() {
    let server = start().await;
    let all = call(&server, "GET", "help-config-kv?subSys=&key=", None).await;
    let all: Value = serde_json::from_str(&all.text).unwrap();
    let names: Vec<&str> = all["keysHelp"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["key"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "identity_openid",
            "identity_ldap",
            "identity_plugin",
            "identity_tls",
            "api",
            "notify_webhook",
            "notify_amqp",
            "notify_kafka",
            "notify_mqtt",
            "notify_nats",
            "notify_nsq",
            "notify_mysql",
            "notify_postgres",
            "notify_elasticsearch",
            "notify_redis",
            "audit_webhook"
        ]
    );
    let one = call(
        &server,
        "GET",
        "help-config-kv?subSys=identity_ldap&key=server_addr&env",
        None,
    )
    .await;
    let one: Value = serde_json::from_str(&one.text).unwrap();
    assert_eq!(one["subSys"], "identity_ldap");
    assert_eq!(one["keysHelp"][0]["key"], "MINIO_IDENTITY_LDAP_SERVER_ADDR");
    let unknown = call(
        &server,
        "GET",
        "help-config-kv?subSys=storage_class&key=",
        None,
    )
    .await;
    assert_eq!(unknown.status, 400);
}

#[tokio::test]
async fn a_change_the_server_would_refuse_is_refused() {
    let server = start_with(|config| {
        config.config_check = teifs_server::ConfigCheck(Arc::new(|config: &ConfigKv| {
            if config
                .variables()
                .values()
                .any(|v| v.contains("refused.example.com"))
            {
                return Err("it names refused.example.com".to_owned());
            }
            Ok(())
        }));
    })
    .await;
    let refused = call(
        &server,
        "PUT",
        "set-config-kv",
        Some("identity_ldap server_addr=refused.example.com:636"),
    )
    .await;
    assert_eq!(refused.status, 400);
    assert_eq!(refused.code(), "XMinioAdminConfigBadJSON");
    assert!(
        refused.text.contains("refused.example.com"),
        "{}",
        refused.text
    );
    assert_eq!(stored(&server), "", "nothing was kept");
    let history = call(&server, "GET", "list-config-history-kv?count=0", None).await;
    assert_eq!(history.text, "[]");
}
