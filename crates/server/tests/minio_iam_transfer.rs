//! `MinIO`'s IAM export and import (`mc admin cluster iam export|import`): a zip of
//! `iam-assets/*.json` that moves users, groups, policies and service accounts between
//! servers.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::io::{Read as _, Write as _};

use serde_json::{Value, json};
use teifs_crypto::madmin;

#[macro_use]
mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client_as, code, start};
use signing::{signed, signed_response};

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);
const ADMIN: &str = "/minio/admin/v3/";
/// A policy that lets its holder list buckets and nothing else.
const LISTER: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;

async fn call(server: &Server, method: &str, path: &str, body: &[u8]) -> (u16, String) {
    signed(server, ROOT, method, &format!("{ADMIN}{path}"), &[], body).await
}

/// A call with `body` encrypted for the root user's secret.
async fn secret_call(server: &Server, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let body = madmin::encrypt(SECRET_KEY, body.to_string().as_bytes());
    let response =
        signed_response(server, ROOT, method, &format!("{ADMIN}{path}"), &[], &body).await;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    if bytes.is_empty() || !(200..300).contains(&status) {
        return (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        );
    }
    let plain = madmin::decrypt(SECRET_KEY, &bytes).unwrap();
    (status, serde_json::from_slice(&plain).unwrap())
}

async fn export(server: &Server, key: (&str, &str)) -> reqwest::Response {
    signed_response(server, key, "GET", &format!("{ADMIN}export-iam"), &[], &[]).await
}

/// `import-iam-v2` of `zip`: its status and answer.
async fn import(server: &Server, key: (&str, &str), zip: &[u8]) -> (u16, Value) {
    let (status, text) = signed(
        server,
        key,
        "PUT",
        &format!("{ADMIN}import-iam-v2"),
        &[],
        zip,
    )
    .await;
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// The files of a zip, by name.
fn unzip(bytes: &[u8]) -> Vec<(String, Value)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..archive.len())
        .map(|i| {
            let mut file = archive.by_index(i).unwrap();
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            (file.name().to_owned(), serde_json::from_str(&text).unwrap())
        })
        .collect()
}

/// A zip of `iam-assets/` files.
fn zipped(files: &[(&str, Value)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, value) in files {
        zip.start_file(
            format!("iam-assets/{name}"),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(value.to_string().as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

async fn lists(server: &Server, key: (&str, &str)) -> String {
    code(client_as(server, key.0, key.1).list_buckets().send().await)
}

/// A server with a policy, users (one disabled), a group and service accounts, as `mc`
/// makes them.
async fn seeded() -> Server {
    let from = start().await;
    assert_eq!(
        call(
            &from,
            "PUT",
            "add-canned-policy?name=lister",
            LISTER.as_bytes()
        )
        .await
        .0,
        200
    );
    for (user, status) in [("bob", "enabled"), ("carol", "disabled")] {
        let body = json!({"secretKey": format!("{user}-secret-key"), "status": status});
        let path = format!("add-user?accessKey={user}");
        assert_eq!(secret_call(&from, "PUT", &path, &body).await.0, 200);
    }
    let group = json!({"group": "devs", "members": ["carol"], "isRemove": false});
    assert_eq!(
        call(
            &from,
            "PUT",
            "update-group-members",
            group.to_string().as_bytes()
        )
        .await
        .0,
        200
    );
    for attach in [
        json!({"policies": ["lister"], "user": "bob"}),
        json!({"policies": ["readonly"], "group": "devs"}),
    ] {
        let path = "idp/builtin/policy/attach";
        assert_eq!(secret_call(&from, "POST", path, &attach).await.0, 200);
    }
    let account = json!({"accessKey": "bobsvc", "secretKey": "bobsvc-secret-key",
        "targetUser": "bob", "name": "backup"});
    assert_eq!(
        secret_call(&from, "PUT", "add-service-account", &account)
            .await
            .0,
        200
    );
    let mine = json!({"accessKey": "rootsvc", "secretKey": "rootsvc-secret-key"});
    assert_eq!(
        secret_call(&from, "PUT", "add-service-account", &mine)
            .await
            .0,
        200
    );

    from
}

#[tokio::test]
async fn an_export_moves_users_groups_policies_and_service_accounts_to_another_server() {
    let from = seeded().await;
    let response = export(&from, ROOT).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/zip");
    let zip = response.bytes().await.unwrap();
    let files = unzip(&zip);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "iam-assets/policies.json",
            "iam-assets/users.json",
            "iam-assets/groups.json",
            "iam-assets/svcaccts.json",
            "iam-assets/user_mappings.json",
            "iam-assets/group_mappings.json",
            "iam-assets/stsuser_mappings.json",
        ]
    );
    let file = |name: &str| &files.iter().find(|(n, _)| n.ends_with(name)).unwrap().1;
    assert_eq!(
        file("/policies.json")["lister"]["Statement"][0]["Action"],
        "s3:ListAllMyBuckets"
    );
    assert_eq!(
        file("/users.json")["carol"],
        json!({"secretKey": "carol-secret-key", "status": "disabled"})
    );
    assert_eq!(file("/groups.json")["devs"]["members"], json!(["carol"]));
    assert_eq!(file("/user_mappings.json")["bob"]["policy"], "lister");
    assert_eq!(file("/group_mappings.json")["devs"]["policy"], "readonly");
    let accounts = file("/svcaccts.json");
    assert_eq!(accounts["bobsvc"]["parent"], "bob");
    assert_eq!(accounts["bobsvc"]["secretKey"], "bobsvc-secret-key");
    assert_eq!(accounts["bobsvc"]["status"], "on");
    assert_eq!(accounts["bobsvc"]["expiration"], "1970-01-01T00:00:00Z");
    assert_eq!(accounts["rootsvc"]["parent"], ACCESS_KEY);

    let to = start().await;
    let (status, result) = import(&to, ROOT, &zip).await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["added"]["policies"], json!(["lister"]));
    assert_eq!(result["added"]["users"], json!(["bob", "carol"]));
    assert_eq!(result["added"]["groups"], json!(["devs"]));
    assert_eq!(
        result["added"]["serviceAccounts"],
        json!(["bobsvc", "rootsvc"])
    );
    assert_eq!(
        result["added"]["userPolicies"],
        json!([{"bob": ["lister"]}])
    );
    assert_eq!(
        result["added"]["groupPolicies"],
        json!([{"devs": ["readonly"]}])
    );
    assert!(result.get("failed").is_none(), "{result}");
    assert_eq!(lists(&to, ("bob", "bob-secret-key")).await, "ok");
    assert_eq!(lists(&to, ("bobsvc", "bobsvc-secret-key")).await, "ok");
    assert_eq!(lists(&to, ("rootsvc", "rootsvc-secret-key")).await, "ok");
    assert_ne!(lists(&to, ("carol", "carol-secret-key")).await, "ok");

    // Again: the service accounts are replaced, the rest set as it is.
    let (status, result) = import(&to, ROOT, &zip).await;
    assert_eq!(status, 200, "{result}");
    assert!(result.get("failed").is_none(), "{result}");
    // The first version answers nothing.
    let (status, text) = call(&to, "PUT", "import-iam", &zip).await;
    assert_eq!((status, text.as_str()), (200, ""));
}

#[tokio::test]
async fn an_import_skips_built_in_policies_removes_empty_ones_and_lists_failures() {
    let server = start().await;
    assert_eq!(
        call(
            &server,
            "PUT",
            "add-canned-policy?name=old",
            LISTER.as_bytes()
        )
        .await
        .0,
        200
    );
    let readonly: Value = serde_json::from_str(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]}"#,
    )
    .unwrap();
    let zip = zipped(&[
        (
            "policies.json",
            json!({"readonly": readonly, "old": {"Version": "2012-10-17", "Statement": []}}),
        ),
        (
            "users.json",
            json!({"dave": {"secretKey": "dave-secret-key", "status": "enabled"}}),
        ),
        (
            "user_mappings.json",
            json!({"dave": {"version": 1, "policy": "no-such-policy"}}),
        ),
        (
            "stsuser_mappings.json",
            json!({"not-a-dn": {"version": 1, "policy": "readonly"}}),
        ),
    ]);
    let (status, result) = import(&server, ROOT, &zip).await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["removed"]["policies"], json!(["old"]));
    assert_eq!(result["added"]["users"], json!(["dave"]));
    let failed = &result["failed"];
    assert_eq!(failed["userPolicies"][0]["name"], "dave");
    assert_eq!(
        failed["userPolicies"][0]["policies"],
        json!(["no-such-policy"])
    );
    assert_eq!(failed["stsPolicies"][0]["name"], "not-a-dn");
    // `MinIO` exports its built-in policies with the rest; they're left as they are.
    assert_eq!(result["skipped"]["policies"], json!(["readonly"]));
    assert!(result["added"].get("policies").is_none(), "{result}");
}

#[tokio::test]
async fn bad_imports_are_refused() {
    let server = start().await;
    // The root user's own key can't be a user.
    let zip = zipped(&[(
        "users.json",
        json!({ACCESS_KEY: {"secretKey": "some-other-secret", "status": "enabled"}}),
    )]);
    let (status, error) = import(&server, ROOT, &zip).await;
    assert_eq!(
        (status, &error["Code"]),
        (403, &json!("XMinioInvalidIAMCredentials"))
    );
    let (status, error) = import(&server, ROOT, b"not a zip").await;
    assert_eq!((status, &error["Code"]), (400, &json!("InvalidRequest")));
    let zip = zipped(&[("users.json", json!(["not", "a", "map"]))]);
    let (status, error) = import(&server, ROOT, &zip).await;
    assert_eq!(
        (status, &error["Code"]),
        (400, &json!("XMinioAdminConfigBadJSON"))
    );

    // Secrets travel in the zip: only the root user exports or imports one, whatever
    // admin actions another has.
    let body = json!({"secretKey": "admin-secret-key", "status": "enabled"});
    assert_eq!(
        secret_call(&server, "PUT", "add-user?accessKey=admin", &body)
            .await
            .0,
        200
    );
    let attach = json!({"policies": ["consoleAdmin"], "user": "admin"});
    assert_eq!(
        secret_call(&server, "POST", "idp/builtin/policy/attach", &attach)
            .await
            .0,
        200
    );
    let admin = ("admin", "admin-secret-key");
    assert_eq!(export(&server, admin).await.status(), 403);
    assert_eq!(import(&server, admin, &zipped(&[])).await.0, 403);
}
