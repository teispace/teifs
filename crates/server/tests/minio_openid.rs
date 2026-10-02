//! `MinIO`'s service accounts of OpenID Connect users: a web identity's session makes
//! its own, which act as the user with the policies the session had, and
//! `idp/openid/list-access-keys-bulk` lists them by user.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::primitives::ByteStream;
use serde_json::{Value, json};
use teifs_crypto::madmin;

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, client_as, code, idp::Idp, start};
use signing::signed_response;

/// Who signs: an access key, its secret, and a session's token.
#[derive(Clone)]
struct Key {
    id: String,
    secret: String,
    token: Option<String>,
}

fn root() -> Key {
    Key {
        id: ACCESS_KEY.to_owned(),
        secret: SECRET_KEY.to_owned(),
        token: None,
    }
}

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;

/// A call with `body` encrypted for the key's secret, and its answer decrypted when it
/// succeeds.
async fn secret_call(
    server: &Server,
    key: &Key,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let body = body.map_or_else(Vec::new, |b| {
        madmin::encrypt(&key.secret, b.to_string().as_bytes())
    });
    let headers: Vec<(&str, &str)> = key
        .token
        .as_deref()
        .map(|token| ("x-amz-security-token", token))
        .into_iter()
        .collect();
    let response = signed_response(
        server,
        (&key.id, &key.secret),
        method,
        &format!("/minio/admin/v3/{path}"),
        &headers,
        &body,
    )
    .await;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    if !(200..300).contains(&status) {
        return (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        );
    }
    if bytes.is_empty() {
        return (status, Value::Null);
    }
    let plain = madmin::decrypt(&key.secret, &bytes).unwrap();
    (status, serde_json::from_slice(&plain).unwrap())
}

fn between<'a>(body: &'a str, start: &str, end: &str) -> &'a str {
    let from = body.find(start).unwrap() + start.len();
    &body[from..from + body[from..].find(end).unwrap()]
}

/// A server with a bucket `photos`, the policy `read-photos`, and a provider whose
/// tokens name policies.
async fn openid_server(idp: &Idp) -> Server {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    root.put_object()
        .bucket("photos")
        .key("cat.jpg")
        .body(ByteStream::from_static(b"meow"))
        .send()
        .await
        .unwrap();
    server
        .iam
        .create_policy("read-photos", None, None, READ_PHOTOS, &[])
        .unwrap();
    server
        .iam
        .create_oidc_provider(&teifs_iam::NewOidcProvider {
            url: &idp.url,
            client_ids: &["sts.amazonaws.com".to_owned()],
            thumbprints: &[],
            tags: &[("teifs:policy-claim".to_owned(), String::new())],
        })
        .unwrap();
    server
}

/// `sub`'s web identity session, as `MinIO`'s clients ask for it, with `extra` in the
/// form.
async fn session(server: &Server, idp: &Idp, sub: &str, extra: &str) -> Key {
    let token = idp.token(sub, r#","policy":"read-photos""#);
    let response = reqwest::Client::new()
        .post(format!("{}/", server.endpoint))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken={token}{extra}"
        ))
        .send()
        .await
        .unwrap();
    let body = response.text().await.unwrap();
    Key {
        id: between(&body, "<AccessKeyId>", "<").to_owned(),
        secret: between(&body, "<SecretAccessKey>", "<").to_owned(),
        token: Some(between(&body, "<SessionToken>", "<").to_owned()),
    }
}

/// The key an `add-service-account` answer made.
fn made(answer: &Value) -> Key {
    let credentials = &answer["credentials"];
    Key {
        id: credentials["accessKey"].as_str().unwrap().to_owned(),
        secret: credentials["secretKey"].as_str().unwrap().to_owned(),
        token: None,
    }
}

async fn reads_photos(server: &Server, key: &Key) -> String {
    code(
        client_as(server, &key.id, &key.secret)
            .get_object()
            .bucket("photos")
            .key("cat.jpg")
            .send()
            .await,
    )
}

#[tokio::test]
async fn openid_users_make_list_and_delete_their_own_service_accounts() {
    let idp = Idp::start().await;
    let server = openid_server(&idp).await;
    let alice = session(&server, &idp, "alice", "").await;
    let name = teifs_iam::openid_parent("alice", &idp.url);

    // `mc admin accesskey create` with the session: the user's own, as the session.
    let (status, answer) = secret_call(
        &server,
        &alice,
        "PUT",
        "add-service-account",
        Some(&json!({"name": "backup"})),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    let account = made(&answer);
    assert_eq!(reads_photos(&server, &account).await, "ok");
    let wrote = client_as(&server, &account.id, &account.secret)
        .put_object()
        .bucket("photos")
        .key("dog.jpg")
        .body(ByteStream::from_static(b"woof"))
        .send()
        .await;
    assert_eq!(code(wrote), "AccessDenied");

    // Listed and described as the user's, by `MinIO`'s name for it.
    let (status, listed) = secret_call(&server, &alice, "GET", "list-service-accounts", None).await;
    assert_eq!(status, 200, "{listed}");
    let accounts = listed["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["accessKey"], account.id.as_str());
    assert_eq!(accounts[0]["parentUser"], name.as_str());
    let path = format!("info-service-account?accessKey={}", account.id);
    let (status, info) = secret_call(&server, &alice, "GET", &path, None).await;
    assert_eq!(status, 200, "{info}");
    assert_eq!(info["parentUser"], name.as_str());
    assert_eq!(info["impliedPolicy"], true);
    assert!(
        info["policy"].as_str().unwrap().contains("photos"),
        "{info}"
    );
    // The account is the user too: it sees its siblings.
    let (status, listed) =
        secret_call(&server, &account, "GET", "list-service-accounts", None).await;
    assert_eq!(
        (status, listed["accounts"].as_array().unwrap().len()),
        (200, 1)
    );

    // By user, as `mc idp openid accesskey ls` lists them.
    let expected = json!([{"configName": "_", "users": [{
        "minioAccessKey": name, "ID": "alice", "readableName": "",
        "serviceAccounts": [accounts[0]], "stsKeys": []}]}]);
    let path = "idp/openid/list-access-keys-bulk?listType=all&all=true";
    let (status, bulk) = secret_call(&server, &root(), "GET", path, None).await;
    assert_eq!((status, &bulk), (200, &expected));
    let path = "idp/openid/list-access-keys-bulk?listType=svcacc-only";
    let (status, bulk) = secret_call(&server, &alice, "GET", path, None).await;
    assert_eq!((status, &bulk), (200, &expected));
    let path = "idp/openid/list-access-keys-bulk?listType=sts-only&users=alice";
    let (status, bulk) = secret_call(&server, &root(), "GET", path, None).await;
    assert_eq!(
        (status, bulk),
        (200, json!([{"configName": "_", "users": []}]))
    );

    // Another user's session neither sees nor deletes them.
    let bob = session(&server, &idp, "bob", "").await;
    let path = format!("info-service-account?accessKey={}", account.id);
    assert_eq!(secret_call(&server, &bob, "GET", &path, None).await.0, 403);
    let path = format!("delete-service-account?accessKey={}", account.id);
    assert_eq!(
        secret_call(&server, &bob, "DELETE", &path, None).await.0,
        404
    );
    let path = "idp/openid/list-access-keys-bulk?listType=all";
    let (status, bulk) = secret_call(&server, &bob, "GET", path, None).await;
    assert_eq!((status, bulk[0]["users"].clone()), (200, json!([])));
    // A session a session policy narrows can't make keys with all the user may do.
    let policy = "&Policy=%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3A*%22%2C%22Resource%22%3A%22*%22%7D%5D%7D";
    let narrowed = session(&server, &idp, "alice", policy).await;
    let (status, _) = secret_call(
        &server,
        &narrowed,
        "PUT",
        "add-service-account",
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, 403);
    // Nor does the account revoke anyone's sessions: none of them are its user's.
    let (status, _) = secret_call(
        &server,
        &account,
        "POST",
        "revoke-tokens/builtin?fullRevoke=true",
        None,
    )
    .await;
    assert_eq!(status, 403);

    // The user deletes its own.
    let path = format!("delete-service-account?accessKey={}", account.id);
    assert_eq!(
        secret_call(&server, &alice, "DELETE", &path, None).await.0,
        204
    );
    assert_eq!(reads_photos(&server, &account).await, "InvalidAccessKeyId");
}

#[tokio::test]
async fn openid_service_accounts_move_with_iam_and_go_with_their_provider() {
    let idp = Idp::start().await;
    let server = openid_server(&idp).await;
    let alice = session(&server, &idp, "alice", "").await;
    let (status, answer) = secret_call(
        &server,
        &alice,
        "PUT",
        "add-service-account",
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    let account = made(&answer);

    // Exported with what names its user, and made again from it.
    let export = server.iam.export(true);
    let exported = &export.service_accounts[0];
    let openid = exported.openid.as_ref().unwrap();
    assert_eq!(
        (exported.parent.as_deref(), openid.provider.as_str()),
        (None, idp.url.as_str())
    );
    assert_eq!(
        (openid.sub.as_str(), openid.aud.as_str()),
        ("alice", "sts.amazonaws.com")
    );
    assert_eq!(openid.policies, ["read-photos"]);
    let other = start().await;
    other.iam.import(&export, true).unwrap();
    let root = client(&other, SECRET_KEY);
    root.create_bucket().bucket("photos").send().await.unwrap();
    root.put_object()
        .bucket("photos")
        .key("cat.jpg")
        .body(ByteStream::from_static(b"meow"))
        .send()
        .await
        .unwrap();
    assert_eq!(reads_photos(&other, &account).await, "ok");

    // Deleting the provider deletes its users' accounts.
    let arn = server.iam.oidc_providers().unwrap()[0].arn.clone();
    server.iam.delete_oidc_provider(&arn).unwrap();
    assert_eq!(reads_photos(&server, &account).await, "InvalidAccessKeyId");
    assert!(server.iam.export(false).service_accounts.is_empty());
}
