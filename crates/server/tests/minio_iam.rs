//! Users, groups and policies through `MinIO`'s admin API, as `mc admin user`, `group` and
//! `policy` call it: secrets in bodies encrypted with the caller's secret key.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use serde_json::{Value, json};
use teifs_crypto::madmin;

#[macro_use]
mod common;
mod signing;

use aws_sdk_s3::types::{
    BucketVersioningStatus, DefaultRetention, ObjectLockConfiguration, ObjectLockEnabled,
    ObjectLockRetentionMode, ObjectLockRule, VersioningConfiguration,
};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, client_as, code, start};
use signing::{signed, signed_response};

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);
const ADMIN: &str = "/minio/admin/v3/";
/// A policy that lets its holder list buckets and nothing else.
const LISTER: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;

/// A call with a plain body: its status and its answer as JSON (or text).
async fn call(
    server: &Server,
    key: (&str, &str),
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, Value) {
    let (status, text) = signed(server, key, method, &format!("{ADMIN}{path}"), &[], body).await;
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// A call with `body` encrypted for `key`'s secret, and its answer decrypted when it
/// succeeds.
async fn secret_call(
    server: &Server,
    key: (&str, &str),
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let body = body.map_or_else(Vec::new, |b| {
        madmin::encrypt(key.1, b.to_string().as_bytes())
    });
    let response =
        signed_response(server, key, method, &format!("{ADMIN}{path}"), &[], &body).await;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    if status != 200 {
        return (status, serde_json::from_slice(&bytes).unwrap());
    }
    if bytes.is_empty() {
        return (status, Value::Null);
    }
    let plain = madmin::decrypt(key.1, &bytes).unwrap();
    (status, serde_json::from_slice(&plain).unwrap())
}

async fn add_user(server: &Server, key: (&str, &str), name: &str, secret: &str) -> (u16, Value) {
    let body = json!({"secretKey": secret, "status": "enabled"});
    secret_call(
        server,
        key,
        "PUT",
        &format!("add-user?accessKey={name}"),
        Some(&body),
    )
    .await
}

/// `update-group-members` of group `devs`, as the root user.
async fn members(server: &Server, members: &[&str], remove: bool) -> (u16, Value) {
    let body = json!({"group": "devs", "members": members, "isRemove": remove}).to_string();
    call(server, ROOT, "PUT", "update-group-members", body.as_bytes()).await
}

/// Whether `key` may list buckets.
async fn lists(server: &Server, key: (&str, &str)) -> String {
    code(client_as(server, key.0, key.1).list_buckets().send().await)
}

fn error(code: &str) -> Value {
    json!(code)
}

#[tokio::test]
async fn users_are_made_given_policies_and_disabled_as_mc_does() {
    let server = start().await;
    assert_eq!(
        add_user(&server, ROOT, "alice", "alice-secret").await.0,
        200
    );
    let alice = ("alice", "alice-secret");
    let (status, info) = call(&server, ROOT, "GET", "user-info?accessKey=alice", b"").await;
    assert_eq!(status, 200);
    assert_eq!(info["status"], "enabled");
    assert!(info.get("policyName").is_none());
    assert_eq!(lists(&server, alice).await, "AccessDenied");

    let attach = json!({"policies": ["readwrite"], "user": "alice"});
    let path = "idp/builtin/policy/attach";
    let (status, answer) = secret_call(&server, ROOT, "POST", path, Some(&attach)).await;
    assert_eq!(
        (status, &answer["policiesAttached"]),
        (200, &json!(["readwrite"]))
    );
    assert_eq!(lists(&server, alice).await, "ok");
    let (status, answer) = secret_call(&server, ROOT, "POST", path, Some(&attach)).await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminPolicyChangeAlreadyApplied"))
    );
    let (status, users) = secret_call(&server, ROOT, "GET", "list-users", None).await;
    assert_eq!(status, 200);
    assert_eq!(users["alice"]["policyName"], "readwrite");

    // Disabled, the user's key doesn't sign; newer clients call `v4`.
    let disable = "/minio/admin/v4/set-user-status?accessKey=alice&status=disabled";
    assert_eq!(signed(&server, ROOT, "PUT", disable, &[], b"").await.0, 200);
    assert_ne!(lists(&server, alice).await, "ok");
    let path = "user-info?accessKey=alice";
    assert_eq!(
        call(&server, ROOT, "GET", path, b"").await.1["status"],
        "disabled"
    );
    let enable = "set-user-status?accessKey=alice&status=enabled";
    assert_eq!(call(&server, ROOT, "PUT", enable, b"").await.0, 200);
    assert_eq!(lists(&server, alice).await, "ok");
    let bad = "set-user-status?accessKey=alice&status=off";
    assert_eq!(call(&server, ROOT, "PUT", bad, b"").await.0, 400);

    // Who has which, then detached: only the user asked about.
    assert_eq!(add_user(&server, ROOT, "bob", "bob-secret").await.0, 200);
    let bob = json!({"policies": ["readonly"], "user": "bob"});
    let path = "idp/builtin/policy/attach";
    assert_eq!(
        secret_call(&server, ROOT, "POST", path, Some(&bob)).await.0,
        200
    );
    let both = json!({"policies": ["readonly"], "user": "bob", "group": "devs"});
    let (status, answer) = secret_call(&server, ROOT, "POST", path, Some(&both)).await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminInvalidArgument"))
    );
    let path = "idp/builtin/policy-entities?user=alice";
    let (status, entities) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(status, 200);
    assert_eq!(
        entities["userMappings"],
        json!([{"user": "alice", "policies": ["readwrite"]}])
    );
    let path = "idp/builtin/policy/detach";
    let (status, answer) = secret_call(&server, ROOT, "POST", path, Some(&attach)).await;
    assert_eq!(
        (status, &answer["policiesDetached"]),
        (200, &json!(["readwrite"]))
    );
    assert_eq!(lists(&server, alice).await, "AccessDenied");

    // Removed with its key.
    assert_eq!(
        call(&server, ROOT, "DELETE", "remove-user?accessKey=alice", b"")
            .await
            .0,
        200
    );
    let (status, answer) = call(&server, ROOT, "GET", "user-info?accessKey=alice", b"").await;
    assert_eq!(
        (status, &answer["Code"]),
        (404, &error("XMinioAdminNoSuchUser"))
    );
    assert_ne!(lists(&server, alice).await, "ok");
}

#[tokio::test]
async fn bad_users_and_bodies_are_refused_as_minio_refuses() {
    let server = start().await;
    // Refused as MinIO refuses.
    let (status, answer) = add_user(&server, ROOT, "x=y", "alice-secret").await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminInvalidAccessKey"))
    );
    let (status, answer) = add_user(&server, ROOT, "carol", "short").await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminInvalidSecretKey"))
    );
    // A body encrypted for another secret, or not at all.
    let body = madmin::encrypt("another-secret", br#"{"secretKey":"carol-secret"}"#);
    let path = format!("{ADMIN}add-user?accessKey=carol");
    let (status, _) = signed(&server, ROOT, "PUT", &path, &[], &body).await;
    assert_eq!(status, 400);
    let (status, _) = signed(
        &server,
        ROOT,
        "PUT",
        &path,
        &[],
        br#"{"secretKey":"carol-secret"}"#,
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = call(&server, ROOT, "GET", "user-info?accessKey=carol", b"").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn canned_policies_are_managed_as_mc_does() {
    let server = start().await;
    let document = LISTER;
    let path = "add-canned-policy?name=lister";
    assert_eq!(
        call(&server, ROOT, "PUT", path, document.as_bytes())
            .await
            .0,
        200
    );
    let (status, answer) = call(&server, ROOT, "PUT", "add-canned-policy?name=bad", b"{").await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioMalformedIAMPolicy"))
    );
    let path = "add-canned-policy?name=readonly";
    let (status, answer) = call(&server, ROOT, "PUT", path, document.as_bytes()).await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminInvalidArgument"))
    );

    let (status, info) = call(
        &server,
        ROOT,
        "GET",
        "info-canned-policy?name=lister&v=2",
        b"",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(info["PolicyName"], "lister");
    assert_eq!(
        info["Policy"]["Statement"][0]["Action"],
        "s3:ListAllMyBuckets"
    );
    let (_, plain) = call(&server, ROOT, "GET", "info-canned-policy?name=lister", b"").await;
    assert_eq!(plain, info["Policy"]);
    let (status, all) = call(&server, ROOT, "GET", "list-canned-policies", b"").await;
    assert_eq!(status, 200);
    assert!(all["lister"].is_object() && all["consoleAdmin"].is_object());

    // A built-in policy overridden, then reset.
    let path = "add-canned-policy?name=readonly&overrideBuiltin=true";
    assert_eq!(
        call(&server, ROOT, "PUT", path, document.as_bytes())
            .await
            .0,
        200
    );
    let (_, plain) = call(
        &server,
        ROOT,
        "GET",
        "info-canned-policy?name=readonly",
        b"",
    )
    .await;
    assert_eq!(plain["Statement"][0]["Action"], "s3:ListAllMyBuckets");
    let path = "add-canned-policy?name=readonly&resetBuiltin=true";
    assert_eq!(call(&server, ROOT, "PUT", path, b"").await.0, 200);
    assert_eq!(
        call(&server, ROOT, "PUT", path, b"").await.0,
        200,
        "nothing to reset"
    );
    let (_, plain) = call(
        &server,
        ROOT,
        "GET",
        "info-canned-policy?name=readonly",
        b"",
    )
    .await;
    assert_ne!(plain["Statement"][0]["Action"], "s3:ListAllMyBuckets");
}

#[tokio::test]
async fn groups_count_for_their_members_while_enabled() {
    let server = start().await;
    assert_eq!(
        add_user(&server, ROOT, "alice", "alice-secret").await.0,
        200
    );
    let alice = ("alice", "alice-secret");
    let path = "add-canned-policy?name=lister";
    assert_eq!(
        call(&server, ROOT, "PUT", path, LISTER.as_bytes()).await.0,
        200
    );
    assert_eq!(members(&server, &["alice"], false).await.0, 200);
    let attach = json!({"policies": ["lister"], "group": "devs"});
    let path = "idp/builtin/policy/attach";
    assert_eq!(
        secret_call(&server, ROOT, "POST", path, Some(&attach))
            .await
            .0,
        200
    );
    assert_eq!(lists(&server, alice).await, "ok");
    let (status, group) = call(&server, ROOT, "GET", "group?group=devs", b"").await;
    assert_eq!(status, 200);
    assert_eq!(
        (&group["members"], &group["policy"], &group["status"]),
        (&json!(["alice"]), &json!("lister"), &json!("enabled"))
    );
    assert_eq!(
        call(&server, ROOT, "GET", "groups", b"").await.1,
        json!(["devs"])
    );
    let path = "set-group-status?group=devs&status=disabled";
    assert_eq!(call(&server, ROOT, "PUT", path, b"").await.0, 200);
    assert_eq!(lists(&server, alice).await, "AccessDenied");

    // A policy in use stays; a group goes once it's empty.
    let remove = "remove-canned-policy?name=lister";
    let (status, answer) = call(&server, ROOT, "DELETE", remove, b"").await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioIAMPolicyInUse"))
    );
    let (status, answer) = members(&server, &[], true).await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminGroupNotEmpty"))
    );
    assert_eq!(members(&server, &["alice"], true).await.0, 200);
    assert_eq!(members(&server, &[], true).await.0, 200);
    let (status, answer) = call(&server, ROOT, "GET", "group?group=devs", b"").await;
    assert_eq!(
        (status, &answer["Code"]),
        (404, &error("XMinioAdminNoSuchGroup"))
    );
    assert_eq!(call(&server, ROOT, "DELETE", remove, b"").await.0, 200);
    let (status, _) = call(&server, ROOT, "GET", "info-canned-policy?name=lister", b"").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn a_user_reads_itself_and_changes_its_own_secret_and_nothing_else() {
    let server = start().await;
    for (name, secret) in [("bob", "bob-secret"), ("alice", "alice-secret")] {
        assert_eq!(add_user(&server, ROOT, name, secret).await.0, 200);
    }
    let bob = ("bob", "bob-secret");
    assert_eq!(
        call(&server, bob, "GET", "user-info?accessKey=bob", b"")
            .await
            .0,
        200
    );
    let (status, answer) = call(&server, bob, "GET", "user-info?accessKey=alice", b"").await;
    assert_eq!((status, &answer["Code"]), (403, &error("AccessDenied")));
    assert_eq!(add_user(&server, bob, "carol", "carol-secret").await.0, 403);
    assert_eq!(
        call(&server, bob, "GET", "list-canned-policies", b"")
            .await
            .0,
        403
    );
    let (status, _) = secret_call(&server, bob, "GET", "list-users", None).await;
    assert_eq!(status, 403);

    // `mc admin user add` of its own key, then `change-my-password`.
    assert_eq!(add_user(&server, bob, "bob", "bob-second").await.0, 200);
    let bob = ("bob", "bob-second");
    let body = json!({"secretKey": "bob-third"});
    let (status, _) = secret_call(&server, bob, "POST", "change-my-password", Some(&body)).await;
    assert_eq!(status, 200);
    assert_ne!(
        call(&server, bob, "GET", "user-info?accessKey=bob", b"")
            .await
            .0,
        200
    );
    let bob = ("bob", "bob-third");
    assert_eq!(
        call(&server, bob, "GET", "user-info?accessKey=bob", b"")
            .await
            .0,
        200
    );

    // An explicit deny takes even that away.
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["admin:ChangeMyPassword","admin:CreateUser","admin:GetUser"],"Resource":"*"}]}"#;
    let path = "add-canned-policy?name=no-self";
    assert_eq!(
        call(&server, ROOT, "PUT", path, deny.as_bytes()).await.0,
        200
    );
    let attach = json!({"policies": ["no-self"], "user": "bob"});
    let path = "idp/builtin/policy/attach";
    assert_eq!(
        secret_call(&server, ROOT, "POST", path, Some(&attach))
            .await
            .0,
        200
    );
    assert_eq!(
        call(&server, bob, "GET", "user-info?accessKey=bob", b"")
            .await
            .0,
        403
    );
    let body = json!({"secretKey": "bob-fourth"});
    let (status, _) = secret_call(&server, bob, "POST", "change-my-password", Some(&body)).await;
    assert_eq!(status, 403);
    assert_eq!(add_user(&server, bob, "bob", "bob-fourth").await.0, 403);

    // The root key isn't a user's.
    let body = json!({"secretKey": "root-secret-new"});
    let (status, answer) =
        secret_call(&server, ROOT, "POST", "change-my-password", Some(&body)).await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminInvalidAccessKey"))
    );
    let (status, _) = add_user(&server, ROOT, ACCESS_KEY, "root-secret-new").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn an_admin_with_some_admin_actions_does_only_those() {
    let server = start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:CreateUser","admin:GetUser"]}]}"#;
    assert_eq!(
        call(
            &server,
            ROOT,
            "PUT",
            "add-canned-policy?name=creator",
            policy.as_bytes()
        )
        .await
        .0,
        200
    );
    assert_eq!(
        add_user(&server, ROOT, "admin1", "admin1-secret").await.0,
        200
    );
    let attach = json!({"policies": ["creator"], "user": "admin1"});
    let path = "idp/builtin/policy/attach";
    assert_eq!(
        secret_call(&server, ROOT, "POST", path, Some(&attach))
            .await
            .0,
        200
    );
    let admin = ("admin1", "admin1-secret");
    assert_eq!(add_user(&server, admin, "dave", "dave-secret").await.0, 200);
    assert_eq!(
        call(&server, admin, "GET", "user-info?accessKey=dave", b"")
            .await
            .0,
        200
    );
    let attach = json!({"policies": ["consoleAdmin"], "user": "admin1"});
    assert_eq!(
        secret_call(&server, admin, "POST", path, Some(&attach))
            .await
            .0,
        403
    );
    assert_eq!(
        call(&server, admin, "DELETE", "remove-user?accessKey=dave", b"")
            .await
            .0,
        403
    );
    let path = "set-user-status?accessKey=dave&status=disabled";
    assert_eq!(call(&server, admin, "PUT", path, b"").await.0, 403);
    // Unsigned: refused.
    let url = format!("{}{ADMIN}groups", server.endpoint);
    assert_eq!(reqwest::get(url).await.unwrap().status().as_u16(), 403);
}

#[tokio::test]
async fn an_admin_can_remove_or_disable_others_but_not_itself() {
    let server = start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:DeleteUser","admin:EnableUser"]}]}"#;
    let path = "add-canned-policy?name=remover";
    assert_eq!(
        call(&server, ROOT, "PUT", path, policy.as_bytes()).await.0,
        200
    );
    for name in ["admin1", "erin", "frank"] {
        assert_eq!(add_user(&server, ROOT, name, "some-secret").await.0, 200);
    }
    let attach = json!({"policies": ["remover"], "user": "admin1"});
    let path = "idp/builtin/policy/attach";
    assert_eq!(
        secret_call(&server, ROOT, "POST", path, Some(&attach))
            .await
            .0,
        200
    );
    let admin = ("admin1", "some-secret");
    let path = "set-user-status?accessKey=erin&status=disabled";
    assert_eq!(call(&server, admin, "PUT", path, b"").await.0, 200);
    assert_eq!(
        call(&server, admin, "DELETE", "remove-user?accessKey=frank", b"")
            .await
            .0,
        200
    );
    let path = "set-user-status?accessKey=admin1&status=disabled";
    let (status, answer) = call(&server, admin, "PUT", path, b"").await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminInvalidArgument"))
    );
    let (status, answer) = call(
        &server,
        admin,
        "DELETE",
        "remove-user?accessKey=admin1",
        b"",
    )
    .await;
    assert_eq!(
        (status, &answer["Code"]),
        (400, &error("XMinioAdminInvalidArgument"))
    );
    let (_, info) = call(&server, ROOT, "GET", "user-info?accessKey=admin1", b"").await;
    assert_eq!(info["status"], "enabled");
}

/// Buckets with something to show: `photos` with an object and a quota, `vault` with
/// Object Lock and a default retention, `old` with versioning suspended.
async fn buckets(server: &Server) {
    let root = client(server, SECRET_KEY);
    for bucket in ["old", "photos"] {
        root.create_bucket().bucket(bucket).send().await.unwrap();
    }
    for status in [
        BucketVersioningStatus::Enabled,
        BucketVersioningStatus::Suspended,
    ] {
        root.put_bucket_versioning()
            .bucket("old")
            .versioning_configuration(VersioningConfiguration::builder().status(status).build())
            .send()
            .await
            .unwrap();
    }
    root.create_bucket()
        .bucket("vault")
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    let retention = DefaultRetention::builder()
        .mode(ObjectLockRetentionMode::Governance)
        .days(3)
        .build();
    root.put_object_lock_configuration()
        .bucket("vault")
        .object_lock_configuration(
            ObjectLockConfiguration::builder()
                .object_lock_enabled(ObjectLockEnabled::Enabled)
                .rule(
                    ObjectLockRule::builder()
                        .default_retention(retention)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    root.put_object()
        .bucket("photos")
        .key("cat.jpg")
        .body(b"meow".to_vec().into())
        .send()
        .await
        .unwrap();
    let quota = br#"{"quota":4096,"quotatype":"hard"}"#;
    let path = "/minio/admin/v3/set-bucket-quota?bucket=photos";
    assert_eq!(signed(server, ROOT, "PUT", path, &[], quota).await.0, 200);
}

/// The buckets `accountinfo` lists for `key`: names and access.
async fn account_buckets(server: &Server, key: (&str, &str)) -> (Value, Vec<(Value, Value)>) {
    let (status, info) = call(server, key, "GET", "accountinfo", b"").await;
    assert_eq!(status, 200);
    let buckets = info["Buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| (b["name"].clone(), b["access"].clone()))
        .collect();
    (info, buckets)
}

#[tokio::test]
async fn account_info_shows_the_root_user_every_bucket_and_what_it_has() {
    let server = start().await;
    buckets(&server).await;
    let (info, names) = account_buckets(&server, ROOT).await;
    assert_eq!(info["AccountName"], ACCESS_KEY);
    assert_eq!(info["Server"]["Type"], 1);
    assert!(info["Policy"]["Statement"].to_string().contains("admin:*"));
    let both = json!({"read": true, "write": true});
    assert_eq!(
        names,
        [
            (json!("old"), both.clone()),
            (json!("photos"), both.clone()),
            (json!("vault"), both)
        ]
    );
    let [old, photos, vault] = [0, 1, 2].map(|i| info["Buckets"][i]["details"].clone());
    assert_eq!(
        (
            &old["versioning"],
            &old["versioningSuspended"],
            &old["locking"]
        ),
        (&json!(false), &json!(true), &json!(false))
    );
    let photos_held = &info["Buckets"][1];
    assert_eq!(
        (&photos_held["size"], &photos_held["objects"]),
        (&json!(4), &json!(1))
    );
    assert_eq!(
        (&photos["quota"]["size"], &photos["versioning"]),
        (&json!(4096), &json!(false))
    );
    assert_eq!(
        (&vault["locking"], &vault["versioning"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(vault["retention"], json!({"mode": "GOVERNANCE", "days": 3}));
}

#[tokio::test]
async fn account_info_shows_a_user_its_policies_and_the_buckets_it_may_use() {
    let server = start().await;
    buckets(&server).await;
    assert_eq!(
        add_user(&server, ROOT, "alice", "alice-secret").await.0,
        200
    );
    let alice = ("alice", "alice-secret");
    let (info, names) = account_buckets(&server, alice).await;
    assert_eq!(info["AccountName"], "alice");
    assert_eq!(info["Policy"]["Statement"], json!([]));
    assert!(names.is_empty());

    // Its policies and its enabled groups'.
    let reader = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::photos"}}"#;
    let path = "add-canned-policy?name=photo-lister";
    assert_eq!(
        call(&server, ROOT, "PUT", path, reader.as_bytes()).await.0,
        200
    );
    let attach = json!({"policies": ["photo-lister"], "user": "alice"});
    let path = "idp/builtin/policy/attach";
    assert_eq!(
        secret_call(&server, ROOT, "POST", path, Some(&attach))
            .await
            .0,
        200
    );
    assert_eq!(members(&server, &["alice"], false).await.0, 200);
    let attach = json!({"policies": ["writeonly"], "group": "devs"});
    assert_eq!(
        secret_call(&server, ROOT, "POST", path, Some(&attach))
            .await
            .0,
        200
    );
    let (info, names) = account_buckets(&server, alice).await;
    let write = json!({"read": false, "write": true});
    assert_eq!(
        names,
        [
            (json!("old"), write.clone()),
            (json!("photos"), json!({"read": true, "write": true})),
            (json!("vault"), write)
        ]
    );
    assert_eq!(info["Policy"]["Statement"].as_array().unwrap().len(), 2);
    let path = "set-group-status?group=devs&status=disabled";
    assert_eq!(call(&server, ROOT, "PUT", path, b"").await.0, 200);
    let (info, names) = account_buckets(&server, alice).await;
    assert_eq!(info["Policy"]["Statement"][0]["Action"], "s3:ListBucket");
    assert_eq!(
        names,
        [(json!("photos"), json!({"read": true, "write": false}))]
    );
}
