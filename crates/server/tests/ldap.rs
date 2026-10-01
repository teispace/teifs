//! LDAP sign-in through a real server: mappings over the admin API, sessions from
//! `AssumeRoleWithLDAPIdentity` used for S3, against the fake directory; and, when
//! `TEIFS_TEST_LDAP_SERVER` names one (`host:port`, MinIO's test image
//! `quay.io/minio/openldap`, plain LDAP), against a real `OpenLDAP`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{config::Credentials, primitives::ByteStream};
use teifs_client::{Client as Admin, ClientError, LdapPolicyRequest, Zeroizing};
use teifs_iam::{
    LdapSettings, Transport,
    ldap::fake::{FakeLdap, group},
};

mod common;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, code, start_with};

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;
const PROJECT_A: &str = "cn=projecta,ou=groups,dc=min,dc=io";
const LIZA: &str = "uid=liza,ou=people,dc=min,dc=io";

fn admin(server: &Server, access_key: &str, secret: &str) -> Admin {
    Admin::new(
        &server.endpoint,
        access_key,
        Zeroizing::new(secret.to_owned()),
    )
    .unwrap()
}

/// An S3 client signing with temporary credentials.
fn session_client(
    server: &Server,
    access_key: &str,
    secret: &str,
    token: &str,
) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(&server.endpoint)
        .force_path_style(true)
        .credentials_provider(Credentials::new(
            access_key,
            secret,
            Some(token.to_owned()),
            None,
            "test",
        ))
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn photos(server: &Server) {
    let root = client(server, SECRET_KEY);
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
}

fn api_code(err: &ClientError) -> &str {
    match err {
        ClientError::Api { code, .. } => code,
        other => panic!("not an API error: {other}"),
    }
}

#[tokio::test]
async fn ldap_users_sign_in_with_the_policies_mapped_to_them() {
    let fake = FakeLdap::start().await;
    let settings = fake.settings();
    let server = start_with(|config| config.ldap = Some(settings)).await;
    photos(&server).await;
    let root = admin(&server, ACCESS_KEY, SECRET_KEY);
    let config = root.config().await.unwrap();
    let ldap = config.ldap.unwrap();
    assert_eq!(
        (ldap.transport.as_str(), ldap.user_bases),
        ("plain", vec!["ou=people,dc=min,dc=io".to_owned()])
    );

    // Without a mapping, no session.
    let unsigned = admin(&server, "", "");
    let refused = unsigned
        .assume_role_with_ldap_identity("dillon", "dillon-password", None, None)
        .await
        .unwrap_err();
    assert_eq!(api_code(&refused), "InvalidParameterValue");

    // A group's mapping, the DN given in another spelling.
    let request = LdapPolicyRequest {
        user: None,
        group: Some("CN=ProjectA, OU=groups, DC=min, DC=io".into()),
        policies: vec!["read-photos".into()],
    };
    let attached = root.attach_ldap_policies(&request).await.unwrap();
    assert_eq!(
        (attached.dn.as_str(), attached.entity.as_str()),
        (PROJECT_A, "group")
    );
    assert_eq!(attached.changed, ["read-photos"]);
    let listed = root.ldap_policies(None).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].dn, PROJECT_A);
    let one = root
        .ldap_policies(Some("cn=PROJECTA, ou=Groups, dc=min, dc=io"))
        .await
        .unwrap();
    assert_eq!(one, listed);
    let other = root.ldap_policies(Some(LIZA)).await.unwrap();
    assert!(other.is_empty());
    let err = root.ldap_policies(Some("not a dn")).await.unwrap_err();
    assert_eq!(api_code(&err), "InvalidArgument");

    let credentials = unsigned
        .assume_role_with_ldap_identity("dillon", "dillon-password", None, Some(900))
        .await
        .unwrap();
    let remaining = credentials
        .expires
        .duration_since(std::time::SystemTime::now())
        .unwrap();
    assert!(remaining.as_secs() <= 900 && remaining.as_secs() > 800);
    let s3 = session_client(
        &server,
        &credentials.access_key,
        &credentials.secret_key,
        &credentials.session_token,
    );
    let object = s3
        .get_object()
        .bucket("photos")
        .key("cat.jpg")
        .send()
        .await
        .unwrap();
    assert_eq!(object.body.collect().await.unwrap().into_bytes(), "meow");
    let put = s3
        .put_object()
        .bucket("photos")
        .key("dog.jpg")
        .body(ByteStream::from_static(b"woof"))
        .send()
        .await;
    assert_eq!(code(put), "AccessDenied");

    // A wrong password is refused, as is a missing one.
    let wrong = unsigned
        .assume_role_with_ldap_identity("dillon", "nope", None, None)
        .await
        .unwrap_err();
    assert_eq!(api_code(&wrong), "InvalidParameterValue");

    // Detached, the session can't any more.
    root.detach_ldap_policies(&request).await.unwrap();
    let get = s3.get_object().bucket("photos").key("cat.jpg").send().await;
    assert_eq!(code(get), "AccessDenied");

    drop(fake);
}

#[tokio::test]
async fn ldap_mappings_that_cant_be_made_are_refused() {
    let fake = FakeLdap::start().await;
    let settings = fake.settings();
    let server = start_with(|config| config.ldap = Some(settings)).await;
    photos(&server).await;
    let root = admin(&server, ACCESS_KEY, SECRET_KEY);
    let request = LdapPolicyRequest {
        user: None,
        group: Some(PROJECT_A.into()),
        policies: vec!["read-photos".into()],
    };
    // A DN the directory doesn't have is refused.
    let nobody = LdapPolicyRequest {
        user: Some("uid=nobody,ou=people,dc=min,dc=io".into()),
        group: None,
        policies: vec!["read-photos".into()],
    };
    let err = root.attach_ldap_policies(&nobody).await.unwrap_err();
    assert_eq!(api_code(&err), "NoSuchEntity");
    let neither = LdapPolicyRequest {
        user: None,
        group: None,
        policies: vec!["read-photos".into()],
    };
    let err = root.attach_ldap_policies(&neither).await.unwrap_err();
    assert_eq!(api_code(&err), "InvalidArgument");
    let both = LdapPolicyRequest {
        user: Some(LIZA.into()),
        ..request.clone()
    };
    let err = root.attach_ldap_policies(&both).await.unwrap_err();
    assert_eq!(api_code(&err), "InvalidArgument");

    // Mapping takes its own permission.
    server.iam.create_user("bob", None, &[], None).unwrap();
    let key = server.iam.create_access_key("bob").unwrap();
    let bob = admin(&server, &key.info.id, &key.secret);
    let err = bob.attach_ldap_policies(&request).await.unwrap_err();
    assert_eq!(api_code(&err), "AccessDenied");
    let err = bob.ldap_policies(None).await.unwrap_err();
    assert_eq!(api_code(&err), "AccessDenied");
    drop(fake);
}

#[tokio::test]
async fn a_user_gone_from_the_directory_loses_its_sessions() {
    let fake = FakeLdap::start().await;
    fake.add(group("projectc", &["liza"]));
    let settings = fake.settings();
    let server = start_with(|config| config.ldap = Some(settings)).await;
    photos(&server).await;
    let root = admin(&server, ACCESS_KEY, SECRET_KEY);
    root.attach_ldap_policies(&LdapPolicyRequest {
        user: Some(LIZA.into()),
        group: None,
        policies: vec!["read-photos".into()],
    })
    .await
    .unwrap();
    let credentials = admin(&server, "", "")
        .assume_role_with_ldap_identity("liza", "liza-password", None, None)
        .await
        .unwrap();
    let s3 = session_client(
        &server,
        &credentials.access_key,
        &credentials.secret_key,
        &credentials.session_token,
    );
    let get = || s3.get_object().bucket("photos").key("cat.jpg").send();
    get().await.unwrap();
    fake.remove(LIZA);
    // What the server's check every few minutes does.
    server.iam.check_ldap_users().await.unwrap();
    assert_eq!(code(get().await), "AccessDenied");
}

#[tokio::test]
async fn a_server_without_ldap_refuses_ldap_calls() {
    let server = start_with(|_| {}).await;
    let root = admin(&server, ACCESS_KEY, SECRET_KEY);
    assert!(root.config().await.unwrap().ldap.is_none());
    let err = admin(&server, "", "")
        .assume_role_with_ldap_identity("dillon", "dillon-password", None, None)
        .await
        .unwrap_err();
    assert_eq!(api_code(&err), "InvalidParameterValue");
    let err = root
        .attach_ldap_policies(&LdapPolicyRequest {
            user: Some("uid=dillon,ou=people,dc=min,dc=io".into()),
            group: None,
            policies: vec!["x".into()],
        })
        .await
        .unwrap_err();
    assert_eq!(api_code(&err), "InvalidInput");
    assert!(root.ldap_policies(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_directory_that_cant_be_asked_is_said_so() {
    // Nothing listens on a port just freed.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = closed.local_addr().unwrap().to_string();
    drop(closed);
    let settings = LdapSettings {
        server: address,
        transport: Transport::Plain,
        lookup_dn: "cn=admin,dc=min,dc=io".into(),
        lookup_password: Some(Zeroizing::new("lookup-password".into())),
        user_bases: vec!["ou=people,dc=min,dc=io".into()],
        user_filter: "(uid=%s)".into(),
        ..LdapSettings::default()
    };
    let server = start_with(|config| config.ldap = Some(settings)).await;
    photos(&server).await;
    let err = admin(&server, ACCESS_KEY, SECRET_KEY)
        .attach_ldap_policies(&LdapPolicyRequest {
            user: Some(LIZA.into()),
            group: None,
            policies: vec!["read-photos".into()],
        })
        .await
        .unwrap_err();
    let ClientError::Api {
        status, message, ..
    } = &err
    else {
        panic!("not an API error: {err}");
    };
    assert_eq!((api_code(&err), *status), ("ServiceUnavailable", 503));
    assert!(message.contains("can't reach the LDAP server"), "{message}");
}

/// MinIO's test directory: `uid=dillon,ou=people,ou=swengg,dc=min,dc=io`, password
/// `dillon`, in groups under `ou=groups,ou=swengg`.
#[tokio::test]
async fn a_real_openldap_signs_users_in() {
    let Ok(address) = std::env::var("TEIFS_TEST_LDAP_SERVER") else {
        eprintln!("skipped: TEIFS_TEST_LDAP_SERVER isn't set");
        return;
    };
    let settings = LdapSettings {
        server: address,
        transport: Transport::Plain,
        lookup_dn: "cn=admin,dc=min,dc=io".into(),
        lookup_password: Some(Zeroizing::new("admin".into())),
        user_bases: vec!["ou=swengg,dc=min,dc=io".into()],
        user_filter: "(uid=%s)".into(),
        user_attributes: vec!["mail".into()],
        group_bases: vec!["ou=swengg,dc=min,dc=io".into()],
        group_filter: Some("(&(objectclass=groupOfNames)(member=%d))".into()),
        ..LdapSettings::default()
    };
    let server = start_with(|config| config.ldap = Some(settings)).await;
    photos(&server).await;
    let root = admin(&server, ACCESS_KEY, SECRET_KEY);
    let dillon = "uid=dillon,ou=people,ou=swengg,dc=min,dc=io";
    // The image seeds its directory after it starts listening.
    let request = LdapPolicyRequest {
        user: Some(dillon.into()),
        group: None,
        policies: vec!["read-photos".into()],
    };
    let mut attached = root.attach_ldap_policies(&request).await;
    for _ in 0..60 {
        if attached.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        attached = root.attach_ldap_policies(&request).await;
    }
    assert_eq!(attached.unwrap().dn, dillon);
    let credentials = admin(&server, "", "")
        .assume_role_with_ldap_identity("dillon", "dillon", None, None)
        .await
        .unwrap();
    let s3 = session_client(
        &server,
        &credentials.access_key,
        &credentials.secret_key,
        &credentials.session_token,
    );
    s3.get_object()
        .bucket("photos")
        .key("cat.jpg")
        .send()
        .await
        .unwrap();
    let wrong = admin(&server, "", "")
        .assume_role_with_ldap_identity("dillon", "wrong", None, None)
        .await
        .unwrap_err();
    assert_eq!(api_code(&wrong), "InvalidParameterValue");
}
