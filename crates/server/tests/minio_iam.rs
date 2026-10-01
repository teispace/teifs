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
    if !(200..300).contains(&status) {
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

/// Attaches canned policy `policy` to user `user`, as the root user.
async fn attach(server: &Server, policy: &str, user: &str) {
    let body = json!({"policies": [policy], "user": user});
    let path = "idp/builtin/policy/attach";
    assert_eq!(
        secret_call(server, ROOT, "POST", path, Some(&body)).await.0,
        200
    );
}

/// `add-service-account` with `body`, as `key`.
async fn add_account(server: &Server, key: (&str, &str), body: &Value) -> (u16, Value) {
    secret_call(server, key, "PUT", "add-service-account", Some(body)).await
}

#[tokio::test]
async fn service_accounts_are_made_listed_changed_and_removed_as_mc_does() {
    let server = start().await;
    assert_eq!(add_user(&server, ROOT, "bob", "bob-secret").await.0, 200);
    attach(&server, "readwrite", "bob").await;
    let bob = ("bob", "bob-secret");

    // `mc admin user svcacct add` of its own: made keys, never expiring, acting as bob.
    let (status, made) = add_account(&server, bob, &json!({"name": "backup"})).await;
    assert_eq!(status, 200);
    let made = &made["credentials"];
    assert_eq!(made["expiration"], "1970-01-01T00:00:00Z");
    let made = (
        made["accessKey"].as_str().unwrap().to_owned(),
        made["secretKey"].as_str().unwrap().to_owned(),
    );
    let svc = (made.0.as_str(), made.1.as_str());
    assert_eq!(lists(&server, svc).await, "ok");

    // Its own keys, narrowed by a policy of its own, expiring in 30 days.
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::days(30))
        .replace_nanosecond(0)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let narrow = json!({"accessKey": "bobreader", "secretKey": "bobreader-secret",
        "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::*"]}]},
        "description": "reads", "expiration": expires});
    let (status, made) = add_account(&server, bob, &narrow).await;
    assert_eq!(status, 200, "{made}");
    assert_eq!(made["credentials"]["expiration"], expires.as_str());
    let reader = ("bobreader", "bobreader-secret");
    assert_eq!(lists(&server, reader).await, "AccessDenied");

    let (status, list) = secret_call(&server, bob, "GET", "list-service-accounts", None).await;
    assert_eq!(status, 200);
    let accounts = list["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0]["accessKey"], svc.0);
    assert_eq!(accounts[0]["name"], "backup");
    assert_eq!(accounts[0]["impliedPolicy"], true);
    assert_eq!(accounts[1]["parentUser"], "bob");
    assert_eq!(accounts[1]["impliedPolicy"], false);

    let path = "info-service-account?accessKey=bobreader";
    let (status, info) = secret_call(&server, bob, "GET", path, None).await;
    assert_eq!(status, 200);
    assert_eq!(info["accountStatus"], "enabled");
    assert_eq!(info["description"], "reads");
    assert_eq!(info["expiration"], expires.as_str());
    assert!(info["policy"].as_str().unwrap().contains("s3:GetObject"));
    let path = format!("info-service-account?accessKey={}", svc.0);
    let (_, info) = secret_call(&server, bob, "GET", &path, None).await;
    assert!(info["policy"].as_str().unwrap().contains("s3:*"), "{info}");
    assert!(info.get("expiration").is_none());

    // Changing one needs `admin:UpdateServiceAccount`, even one's own.
    let path = format!("update-service-account?accessKey={}", svc.0);
    let off = json!({"newStatus": "off"});
    assert_eq!(
        secret_call(&server, bob, "POST", &path, Some(&off)).await.0,
        403
    );
    assert_eq!(
        secret_call(&server, ROOT, "POST", &path, Some(&off))
            .await
            .0,
        204
    );
    assert_ne!(lists(&server, svc).await, "ok");
    let on = json!({"newStatus": "on", "newPolicy": {"Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": ["*"]}]}});
    assert_eq!(
        secret_call(&server, ROOT, "POST", &path, Some(&on)).await.0,
        204
    );
    assert_eq!(lists(&server, svc).await, "ok");
    let bad = json!({"newStatus": "maybe"});
    assert_eq!(
        secret_call(&server, ROOT, "POST", &path, Some(&bad))
            .await
            .0,
        400
    );

    // Deleting its own; then bob's going takes the rest.
    let path = "delete-service-account?accessKey=bobreader";
    assert_eq!(call(&server, bob, "DELETE", path, b"").await.0, 204);
    assert_ne!(lists(&server, reader).await, "ok");
    let (status, answer) = call(&server, bob, "DELETE", path, b"").await;
    assert_eq!(
        (status, &answer["Code"]),
        (404, &error("XMinioInvalidIAMCredentials"))
    );
    assert_eq!(
        call(&server, ROOT, "DELETE", "remove-user?accessKey=bob", b"")
            .await
            .0,
        200
    );
    assert_ne!(lists(&server, svc).await, "ok");
    let path = format!("info-service-account?accessKey={}", svc.0);
    assert_eq!(secret_call(&server, ROOT, "GET", &path, None).await.0, 404);
}

#[tokio::test]
async fn others_service_accounts_need_the_admin_actions() {
    let server = start().await;
    for (name, secret) in [("bob", "bob-secret"), ("alice", "alice-secret")] {
        assert_eq!(add_user(&server, ROOT, name, secret).await.0, 200);
        attach(&server, "readwrite", name).await;
    }
    let (bob, alice) = (("bob", "bob-secret"), ("alice", "alice-secret"));
    let keys = json!({"accessKey": "bobsvc", "secretKey": "bobsvc-secret"});
    assert_eq!(add_account(&server, bob, &keys).await.0, 200);

    // Alice may not see, make or delete bob's.
    let for_bob = json!({"targetUser": "bob"});
    assert_eq!(add_account(&server, alice, &for_bob).await.0, 403);
    let path = "info-service-account?accessKey=bobsvc";
    assert_eq!(secret_call(&server, alice, "GET", path, None).await.0, 403);
    let path = "list-service-accounts?user=bob";
    assert_eq!(secret_call(&server, alice, "GET", path, None).await.0, 403);
    let path = "list-access-keys-bulk?listType=all&users=bob";
    assert_eq!(secret_call(&server, alice, "GET", path, None).await.0, 403);
    let path = "list-access-keys-bulk?listType=all&all=true";
    assert_eq!(secret_call(&server, alice, "GET", path, None).await.0, 403);
    let path = "info-access-key?accessKey=bobsvc";
    assert_eq!(secret_call(&server, alice, "GET", path, None).await.0, 403);
    let path = "delete-service-account?accessKey=bobsvc";
    let (status, answer) = call(&server, alice, "DELETE", path, b"").await;
    assert_eq!(
        (status, &answer["Code"]),
        (404, &error("XMinioInvalidIAMCredentials"))
    );

    // With the actions, she may.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:CreateServiceAccount","admin:ListServiceAccounts","admin:RemoveServiceAccount"]}]}"#;
    let path = "add-canned-policy?name=svc-admin";
    assert_eq!(
        call(&server, ROOT, "PUT", path, policy.as_bytes()).await.0,
        200
    );
    attach(&server, "svc-admin", "alice").await;
    // Every user's keys need `admin:ListUsers` as well.
    let path = "list-access-keys-bulk?listType=all&all=true";
    assert_eq!(secret_call(&server, alice, "GET", path, None).await.0, 403);
    let (status, made) = add_account(&server, alice, &for_bob).await;
    assert_eq!(status, 200);
    let made = made["credentials"]["accessKey"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = "list-service-accounts?user=bob";
    let (_, list) = secret_call(&server, alice, "GET", path, None).await;
    assert_eq!(list["accounts"].as_array().unwrap().len(), 2);
    assert_eq!(list["accounts"][1]["accessKey"], made.as_str());
    let path = "delete-service-account?accessKey=bobsvc";
    assert_eq!(call(&server, alice, "DELETE", path, b"").await.0, 204);
    let nobody = json!({"targetUser": "nobody"});
    let (status, answer) = add_account(&server, alice, &nobody).await;
    assert_eq!(
        (status, &answer["Code"]),
        (404, &error("XMinioAdminNoSuchUser"))
    );
    assert_eq!(
        answer["Message"],
        "Specified target user nobody does not exist"
    );

    // An explicit deny takes even one's own away.
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["admin:CreateServiceAccount","admin:ListServiceAccounts"],"Resource":"*"}]}"#;
    let path = "add-canned-policy?name=no-svc";
    assert_eq!(
        call(&server, ROOT, "PUT", path, deny.as_bytes()).await.0,
        200
    );
    attach(&server, "no-svc", "bob").await;
    assert_eq!(add_account(&server, bob, &json!({})).await.0, 403);
    assert_eq!(
        secret_call(&server, bob, "GET", "list-service-accounts", None)
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn the_root_user_s_service_accounts_and_bad_ones() {
    let server = start().await;
    let (status, made) = add_account(&server, ROOT, &json!({})).await;
    assert_eq!(status, 200);
    let made = &made["credentials"];
    let svc = (
        made["accessKey"].as_str().unwrap().to_owned(),
        made["secretKey"].as_str().unwrap().to_owned(),
    );
    let svc = (svc.0.as_str(), svc.1.as_str());
    assert_eq!(lists(&server, svc).await, "ok");
    let (_, list) = secret_call(&server, ROOT, "GET", "list-service-accounts", None).await;
    assert_eq!(list["accounts"][0]["parentUser"], ACCESS_KEY);
    // The root user's implied policy is `consoleAdmin`'s.
    let path = format!("info-service-account?accessKey={}", svc.0);
    let (_, info) = secret_call(&server, ROOT, "GET", &path, None).await;
    let policy = info["policy"].as_str().unwrap();
    assert!(
        policy.contains("admin:*") && policy.contains("kms:*"),
        "{policy}"
    );
    // A root service account manages its parent's, but isn't the root user.
    let (status, list) = secret_call(&server, svc, "GET", "list-service-accounts", None).await;
    assert_eq!(
        (status, list["accounts"].as_array().unwrap().len()),
        (200, 1)
    );
    let body = json!({"secretKey": "root-secret-new"});
    let (status, _) = secret_call(&server, svc, "POST", "change-my-password", Some(&body)).await;
    assert_ne!(status, 200);

    let refused = [
        (
            json!({"accessKey": "onlykey"}),
            400,
            "XMinioAdminNoSecretKey",
        ),
        (
            json!({"secretKey": "only-secret"}),
            400,
            "XMinioAdminNoAccessKey",
        ),
        (
            json!({"accessKey": ACCESS_KEY, "secretKey": "some-secret"}),
            403,
            "XMinioInvalidIAMCredentials",
        ),
        (
            json!({"accessKey": svc.0, "secretKey": "some-secret"}),
            400,
            "XMinioIAMServiceAccountNotAllowed",
        ),
        (json!({"name": "1st"}), 400, "XMinioInvalidResource"),
        (
            json!({"expiration": "2000-01-01T00:00:00Z"}),
            400,
            "XMinioAdminInvalidArgument",
        ),
    ];
    for (body, status, code) in refused {
        let (got, answer) = add_account(&server, ROOT, &body).await;
        assert_eq!((got, &answer["Code"]), (status, &error(code)), "{body}");
    }
    let (status, _) = add_account(&server, ROOT, &json!({"expiration": "soon"})).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn a_narrowed_key_makes_and_removes_service_accounts_only_with_the_actions() {
    let server = start().await;
    assert_eq!(add_user(&server, ROOT, "bob", "bob-secret").await.0, 200);
    attach(&server, "readwrite", "bob").await;
    let bob = ("bob", "bob-secret");
    let reads = json!({"accessKey": "bobreader", "secretKey": "bobreader-secret",
        "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::*"]}]}});
    assert_eq!(add_account(&server, bob, &reads).await.0, 200);
    let keys = json!({"accessKey": "bobsvc", "secretKey": "bobsvc-secret"});
    assert_eq!(add_account(&server, bob, &keys).await.0, 200);
    let reader = ("bobreader", "bobreader-secret");

    // Bob makes and removes his own; a key narrowed below him may not, or it could
    // make one with all he may do.
    assert_eq!(add_account(&server, reader, &json!({})).await.0, 403);
    let path = "delete-service-account?accessKey=bobsvc";
    assert_eq!(call(&server, reader, "DELETE", path, b"").await.0, 403);
    let (status, list) = secret_call(&server, reader, "GET", "list-service-accounts", None).await;
    assert_eq!(
        (status, list["accounts"].as_array().unwrap().len()),
        (200, 2)
    );

    // With the actions it may.
    let svc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:CreateServiceAccount","admin:RemoveServiceAccount"]}]}"#;
    let path = "add-canned-policy?name=svc-admin";
    assert_eq!(
        call(&server, ROOT, "PUT", path, svc.as_bytes()).await.0,
        200
    );
    attach(&server, "svc-admin", "bob").await;
    let admin = json!({"accessKey": "bobadmin", "secretKey": "bobadmin-secret",
        "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Action": ["admin:CreateServiceAccount", "admin:RemoveServiceAccount"]}]}});
    assert_eq!(add_account(&server, bob, &admin).await.0, 200);
    let admin = ("bobadmin", "bobadmin-secret");
    assert_eq!(add_account(&server, admin, &json!({})).await.0, 200);
    let path = "delete-service-account?accessKey=bobsvc";
    assert_eq!(call(&server, admin, "DELETE", path, b"").await.0, 204);
}

/// Credentials from an `add-service-account` answer.
fn credentials(made: &Value) -> (String, String) {
    let made = &made["credentials"];
    (
        made["accessKey"].as_str().unwrap().to_owned(),
        made["secretKey"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn access_keys_are_listed_and_described_as_mc_admin_accesskey_does() {
    let server = start().await;
    assert_eq!(add_user(&server, ROOT, "bob", "bob-secret").await.0, 200);
    attach(&server, "readwrite", "bob").await;
    let bob = ("bob", "bob-secret");
    let (status, made) = add_account(&server, bob, &json!({})).await;
    assert_eq!(status, 200);
    let made = credentials(&made);
    let svc = (made.0.as_str(), made.1.as_str());
    let keys = json!({"accessKey": "bobreader", "secretKey": "bobreader-secret"});
    assert_eq!(add_account(&server, bob, &keys).await.0, 200);

    let path = "info-access-key?accessKey=bobreader";
    let (status, info) = secret_call(&server, bob, "GET", path, None).await;
    assert_eq!(status, 200);
    assert_eq!(info["AccessKey"], "bobreader");
    assert_eq!(info["userType"], "Service Account");
    assert_eq!(info["parentUser"], "bob");
    let (status, info) = secret_call(&server, svc, "GET", "info-access-key", None).await;
    assert_eq!((status, &info["AccessKey"]), (200, &json!(svc.0)));
    let path = "info-access-key?accessKey=bob";
    assert_eq!(secret_call(&server, bob, "GET", path, None).await.0, 403);
    let (status, answer) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(
        (status, &answer["Code"]),
        (404, &error("XMinioAdminNoSuchAccessKey"))
    );
    let path = "temporary-account-info?accessKey=TSIAANY";
    let (status, answer) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(
        (status, &answer["Code"]),
        (404, &error("XMinioAdminNoSuchAccessKey"))
    );

    let path = "list-access-keys-bulk?listType=svcacc-only";
    let (status, keys) = secret_call(&server, bob, "GET", path, None).await;
    assert_eq!(status, 200);
    assert_eq!(keys["bob"]["serviceAccounts"].as_array().unwrap().len(), 2);
    let path = "list-access-keys-bulk?listType=all&all=true";
    let (status, keys) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(status, 200);
    assert!(
        keys.get(ACCESS_KEY).is_some() && keys.get("bob").is_some(),
        "{keys}"
    );
    let path = "list-access-keys-bulk?listType=svcacc-only&all=true";
    let (_, keys) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(keys.as_object().unwrap().len(), 1, "{keys}");
    let path = "list-access-keys-bulk?listType=sts-only&users=bob";
    let (_, keys) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(keys, json!({}));
    let path = "list-access-keys-bulk?listType=all&all=true&users=bob";
    let (status, answer) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!((status, &answer["Code"]), (400, &error("InvalidRequest")));
    let path = "list-access-keys-bulk?listType=some";
    assert_eq!(secret_call(&server, bob, "GET", path, None).await.0, 400);
}
