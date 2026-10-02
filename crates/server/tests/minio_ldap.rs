//! `MinIO`'s LDAP admin calls, as `mc idp ldap policy` and `mc idp ldap accesskey` make
//! them, against the fake directory: mappings by name or DN, and directory users'
//! service accounts. And `mc idp openid accesskey ls`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::primitives::ByteStream;
use serde_json::{Value, json};
use teifs_client::{Client as Admin, Zeroizing};
use teifs_crypto::madmin;
use teifs_iam::ldap::fake::{FakeLdap, group};

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, client_as, code, start, start_with};
use signing::signed_response;

const ROOT: Key = Key {
    id: ACCESS_KEY,
    secret: SECRET_KEY,
    token: None,
};
const ADMIN: &str = "/minio/admin/v3/";
const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;
const LIZA: &str = "uid=liza,ou=people,dc=min,dc=io";
const PROJECT_A: &str = "cn=projecta,ou=groups,dc=min,dc=io";

/// Who signs: an access key, its secret, and a session's token.
#[derive(Clone, Copy)]
struct Key<'a> {
    id: &'a str,
    secret: &'a str,
    token: Option<&'a str>,
}

/// A call with `body` encrypted for the key's secret, and its answer decrypted when it
/// succeeds.
async fn secret_call(
    server: &Server,
    key: Key<'_>,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let body = body.map_or_else(Vec::new, |b| {
        madmin::encrypt(key.secret, b.to_string().as_bytes())
    });
    let headers: Vec<(&str, &str)> = key
        .token
        .map(|token| ("x-amz-security-token", token))
        .into_iter()
        .collect();
    let response = signed_response(
        server,
        (key.id, key.secret),
        method,
        &format!("{ADMIN}{path}"),
        &headers,
        &body,
    )
    .await;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    if !(200..300).contains(&status) {
        return (status, serde_json::from_slice(&bytes).unwrap());
    }
    let plain = madmin::decrypt(key.secret, &bytes).unwrap();
    (status, serde_json::from_slice(&plain).unwrap())
}

async fn ldap_server(fake: &FakeLdap) -> Server {
    let settings = fake.settings();
    let server = start_with(|config| config.ldap = Some(settings)).await;
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
}

async fn change(server: &Server, operation: &str, body: &Value) -> (u16, Value) {
    let path = format!("idp/ldap/policy/{operation}");
    secret_call(server, ROOT, "POST", &path, Some(body)).await
}

#[tokio::test]
async fn ldap_policies_are_mapped_and_listed_as_mc_idp_ldap_does() {
    let fake = FakeLdap::start().await;
    let server = ldap_server(&fake).await;
    // A user by name, a group by DN in another spelling.
    let (status, changed) = change(
        &server,
        "attach",
        &json!({"policies": ["read-photos"], "user": "liza"}),
    )
    .await;
    assert_eq!(status, 200, "{changed}");
    assert_eq!(changed["policiesAttached"], json!(["read-photos"]));
    assert!(changed["updatedAt"].is_string());
    let group = json!({"policies": ["readonly"], "group": "CN=ProjectA,OU=Groups,DC=min,DC=io"});
    assert_eq!(change(&server, "attach", &group).await.0, 200);

    // What can't be done, as MinIO answers it.
    let again = json!({"policies": ["read-photos"], "user": LIZA});
    let (status, err) = change(&server, "attach", &again).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioAdminPolicyChangeAlreadyApplied"))
    );
    for (body, status, code) in [
        (
            json!({"policies": ["missing"], "user": "liza"}),
            404,
            "XMinioAdminNoSuchPolicy",
        ),
        (
            json!({"policies": ["readonly"], "user": "nobody"}),
            404,
            "XMinioAdminNoSuchUser",
        ),
        (
            json!({"policies": ["readonly"], "group": "cn=nobody,ou=groups,dc=min,dc=io"}),
            404,
            "XMinioAdminNoSuchGroup",
        ),
        (
            json!({"policies": ["readonly"], "user": "liza", "group": PROJECT_A}),
            400,
            "XMinioAdminInvalidArgument",
        ),
    ] {
        let (got, err) = change(&server, "attach", &body).await;
        assert_eq!((got, err["Code"].as_str()), (status, Some(code)), "{body}");
    }

    // Liza signs in with what's mapped to her.
    let credentials = admin_client(&server, "", "")
        .assume_role_with_ldap_identity("liza", "liza-password", None, None)
        .await
        .unwrap();
    let liza = session(&server, &credentials);
    liza.get_object()
        .bucket("photos")
        .key("cat.jpg")
        .send()
        .await
        .unwrap();

    // Every mapping, and one user's with her groups'.
    let (status, all) = secret_call(&server, ROOT, "GET", "idp/ldap/policy-entities", None).await;
    assert_eq!(status, 200, "{all}");
    assert_eq!(
        all["userMappings"],
        json!([{"user": LIZA, "policies": ["read-photos"]}])
    );
    assert_eq!(
        all["groupMappings"],
        json!([{"group": PROJECT_A, "policies": ["readonly"]}])
    );
    assert_eq!(all["policyMappings"].as_array().unwrap().len(), 2);
    let path = "idp/ldap/policy-entities?user=dillon&policy=readonly";
    let (_, dillon) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(
        dillon["userMappings"],
        json!([{"user": "uid=dillon,ou=people,dc=min,dc=io", "policies": [],
            "memberOfMappings": [{"group": PROJECT_A, "policies": ["readonly"]}]}])
    );
    assert_eq!(
        dillon["policyMappings"],
        json!([{"policy": "readonly", "users": [], "groups": [PROJECT_A]}])
    );

    let (status, changed) = change(
        &server,
        "detach",
        &json!({"policies": ["read-photos"], "user": LIZA}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(changed["policiesDetached"], json!(["read-photos"]));
    assert_eq!(
        code(
            liza.get_object()
                .bucket("photos")
                .key("cat.jpg")
                .send()
                .await
        ),
        "AccessDenied"
    );
}

#[tokio::test]
async fn a_server_without_ldap_says_so() {
    let server = start().await;
    for (method, path) in [
        ("GET", "idp/ldap/policy-entities"),
        ("PUT", "idp/ldap/add-service-account"),
        ("GET", "idp/ldap/list-access-keys-bulk?listType=all"),
    ] {
        let (status, err) = secret_call(&server, ROOT, method, path, Some(&json!({}))).await;
        assert_eq!(
            (status, err["Code"].as_str()),
            (501, Some("XMinioLDAPNotEnabled")),
            "{path}"
        );
    }
    let (status, err) = change(
        &server,
        "attach",
        &json!({"policies": ["readonly"], "user": "liza"}),
    )
    .await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (501, Some("XMinioLDAPNotEnabled"))
    );
    let path = "idp/openid/list-access-keys-bulk?listType=all";
    let (status, err) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("OpenIDNotEnabled"))
    );
}

fn admin_client(server: &Server, access_key: &str, secret: &str) -> Admin {
    Admin::new(
        &server.endpoint,
        access_key,
        Zeroizing::new(secret.to_owned()),
    )
    .unwrap()
}

/// An S3 client signing with an LDAP session's credentials.
fn session(
    server: &Server,
    credentials: &teifs_client::TemporaryCredentials,
) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
        .force_path_style(true)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            &credentials.access_key,
            credentials.secret_key.as_str(),
            Some(credentials.session_token.to_string()),
            None,
            "test",
        ))
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

/// The access key and secret of an `add-service-account` answer.
fn made(answer: &Value) -> (String, String) {
    let credentials = &answer["credentials"];
    (
        credentials["accessKey"].as_str().unwrap().to_owned(),
        credentials["secretKey"].as_str().unwrap().to_owned(),
    )
}

async fn reads_photos(server: &Server, (key, secret): (&str, &str)) -> String {
    code(
        client_as(server, key, secret)
            .get_object()
            .bucket("photos")
            .key("cat.jpg")
            .send()
            .await,
    )
}

#[tokio::test]
async fn ldap_users_make_and_list_their_own_service_accounts() {
    let fake = FakeLdap::start().await;
    fake.add(group("projectc", &["liza"]));
    let server = ldap_server(&fake).await;
    let body = json!({"policies": ["read-photos"], "group": "cn=projectc,ou=groups,dc=min,dc=io"});
    assert_eq!(change(&server, "attach", &body).await.0, 200);
    let credentials = admin_client(&server, "", "")
        .assume_role_with_ldap_identity("liza", "liza-password", None, None)
        .await
        .unwrap();
    let liza = Key {
        id: &credentials.access_key,
        secret: &credentials.secret_key,
        token: Some(&credentials.session_token),
    };

    // `mc idp ldap accesskey create` with her session, and `mc admin user svcacct add`.
    let path = "idp/ldap/add-service-account";
    let (status, answer) =
        secret_call(&server, liza, "PUT", path, Some(&json!({"name": "backup"}))).await;
    assert_eq!(status, 200, "{answer}");
    let first = made(&answer);
    assert_eq!(reads_photos(&server, (&first.0, &first.1)).await, "ok");
    let (status, answer) = secret_call(
        &server,
        liza,
        "PUT",
        "add-service-account",
        Some(&json!({"accessKey": "lizareader", "secretKey": "lizareader-secret"})),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        reads_photos(&server, ("lizareader", "lizareader-secret")).await,
        "ok"
    );

    // Hers are listed to her, by DN; others' aren't.
    let (status, mine) = secret_call(&server, liza, "GET", "idp/ldap/list-access-keys", None).await;
    assert_eq!(status, 200, "{mine}");
    let keys: Vec<&str> = mine["serviceAccounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["accessKey"].as_str().unwrap())
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&first.0.as_str()) && keys.contains(&"lizareader"));
    assert_eq!(mine["serviceAccounts"][0]["parentUser"], LIZA);
    let path = "idp/ldap/list-access-keys-bulk?listType=svcacc-only";
    let (status, bulk) = secret_call(&server, liza, "GET", path, None).await;
    assert_eq!(status, 200, "{bulk}");
    assert_eq!(bulk[LIZA]["serviceAccounts"].as_array().unwrap().len(), 2);
    let (status, _) = secret_call(&server, liza, "GET", "list-service-accounts", None).await;
    assert_eq!(status, 200);
    for path in [
        "idp/ldap/list-access-keys?userDN=dillon",
        "idp/ldap/list-access-keys-bulk?listType=all&all=true",
        "idp/ldap/list-access-keys-bulk?listType=all&userDNs=dillon",
    ] {
        let (status, _) = secret_call(&server, liza, "GET", path, None).await;
        assert_eq!(status, 403, "{path}");
    }
    let other = json!({"targetUser": "dillon"});
    let path = "idp/ldap/add-service-account";
    assert_eq!(
        secret_call(&server, liza, "PUT", path, Some(&other))
            .await
            .0,
        403
    );
    // A service account doesn't make others without the action.
    let svc = Key {
        id: &first.0,
        secret: &first.1,
        token: None,
    };
    assert_eq!(
        secret_call(&server, svc, "PUT", path, Some(&json!({})))
            .await
            .0,
        403
    );

    let third = root_makes_one_for_liza(&server).await;
    let path = "idp/ldap/list-access-keys-bulk?listType=all&all=true";
    let (status, all) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(status, 200, "{all}");
    assert_eq!(all[LIZA]["serviceAccounts"].as_array().unwrap().len(), 3);
    assert_eq!(all[LIZA]["stsKeys"], json!([]));
    let path = format!(
        "idp/ldap/list-access-keys?userDN={}",
        LIZA.replace(',', "%2C").replace('=', "%3D")
    );
    let (status, hers) = secret_call(&server, ROOT, "GET", &path, None).await;
    assert_eq!(status, 200, "{hers}");
    assert_eq!(hers["serviceAccounts"].as_array().unwrap().len(), 3);

    // She's removed from the directory: her service accounts go with her.
    fake.remove(LIZA);
    server.iam.check_ldap_users().await.unwrap();
    for key in [
        (&*first.0, &*first.1),
        ("lizareader", "lizareader-secret"),
        (&*third.0, &*third.1),
    ] {
        assert_eq!(reads_photos(&server, key).await, "InvalidAccessKeyId");
    }
}

#[tokio::test]
async fn openid_access_keys_are_listed_by_configuration() {
    let server = start().await;
    server
        .iam
        .create_oidc_provider(&teifs_iam::NewOidcProvider {
            url: "https://accounts.example.com",
            client_ids: &["teifs".to_owned()],
            thumbprints: &[],
            tags: &[],
        })
        .unwrap();
    let path = "idp/openid/list-access-keys-bulk?listType=all&all=true";
    let (status, listed) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed, json!([{"configName": "_", "users": []}]));
    let path = "idp/openid/list-access-keys-bulk?listType=all&configName=other";
    let (status, err) = secret_call(&server, ROOT, "GET", path, None).await;
    assert_eq!(
        (status, err["Code"].as_str()),
        (400, Some("XMinioAdminNoSuchConfigTarget"))
    );
    let path = "idp/openid/list-access-keys-bulk?listType=some";
    assert_eq!(secret_call(&server, ROOT, "GET", path, None).await.0, 400);
}

/// The root user makes a service account for liza by name; not for a DN, an unknown
/// user, or one without policies.
async fn root_makes_one_for_liza(server: &Server) -> (String, String) {
    let path = "idp/ldap/add-service-account";
    let (status, answer) = secret_call(
        server,
        ROOT,
        "PUT",
        path,
        Some(&json!({"targetUser": "liza"})),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    for (target, status, code) in [
        (LIZA, 400, "XMinioLDAPExpectedLoginName"),
        ("nobody", 404, "XMinioAdminNoSuchUser"),
        ("dillon", 404, "XMinioAdminNoSuchUser"),
    ] {
        let (got, err) = secret_call(
            server,
            ROOT,
            "PUT",
            path,
            Some(&json!({"targetUser": target})),
        )
        .await;
        assert_eq!(
            (got, err["Code"].as_str()),
            (status, Some(code)),
            "{target}"
        );
    }
    let (_, err) = secret_call(server, ROOT, "PUT", path, Some(&json!({}))).await;
    assert_eq!(err["Code"], "XMinioAdminNoSuchUser");
    made(&answer)
}
