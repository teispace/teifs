//! Signing in with a client certificate (MinIO's `AssumeRoleWithCertificate`) over a real
//! TLS connection: the server asks for a certificate without requiring one, the session
//! gets the policy the certificate's common name names, and what isn't trusted is
//! refused.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use std::fs;

use aws_sdk_s3::{config::Credentials, primitives::ByteStream};
use common::{ACCESS_KEY, SECRET_KEY, Server, certs::Authority, start_with};
use teifs_client::{Client, ClientError, TemporaryCredentials, Zeroizing};
use teifs_server::{ClientCertificates, TlsSource};

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;

/// A server on HTTPS whose certificates folder has `ca`'s certificate in `CAs`, taking
/// client certificates as `certificates` says.
async fn https(
    ca: &Authority,
    certificates: Option<ClientCertificates>,
) -> (Server, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    ca.issue_into(dir.path(), &["127.0.0.1"]);
    fs::create_dir(dir.path().join("CAs")).unwrap();
    fs::write(dir.path().join("CAs/ca.crt"), &ca.pem).unwrap();
    let source = TlsSource::Dir(dir.path().to_owned());
    let server = start_with(|config| {
        config.tls = Some(source);
        config.client_certificates = certificates;
    })
    .await;
    (server, dir)
}

/// A client of `server` (trusting `ca`) presenting `certificate`, if any.
fn unsigned(
    server: &Server,
    ca: &Authority,
    certificate: Option<&common::certs::Issued>,
) -> Client {
    let client = Client::new(&server.endpoint, "", Zeroizing::new(String::new()))
        .unwrap()
        .with_root_certificates(ca.pem.as_bytes())
        .unwrap();
    match certificate {
        Some(c) => client
            .with_client_certificate(c.cert.as_bytes(), c.key.as_bytes())
            .unwrap(),
        None => client,
    }
}

fn refusal(err: &ClientError) -> (u16, &str, &str) {
    match err {
        ClientError::Api {
            status,
            code,
            message,
            ..
        } => (*status, code, message),
        other => panic!("not an API error: {other}"),
    }
}

fn s3(server: &Server, ca: &Authority, credentials: &TemporaryCredentials) -> aws_sdk_s3::Client {
    ca.client_with(
        server,
        Credentials::new(
            &credentials.access_key,
            credentials.secret_key.as_str(),
            Some(credentials.session_token.to_string()),
            None,
            "test",
        ),
    )
}

#[tokio::test]
async fn a_client_certificate_signs_in_with_the_policy_it_names() {
    let ca = Authority::new();
    let (server, _certs) = https(&ca, Some(ClientCertificates::default())).await;
    let root = ca.client(&server);
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
        .create_policy("readphotos", None, None, READ_PHOTOS, &[])
        .unwrap();

    let leaf = ca.issue_client("readphotos");
    let credentials = unsigned(&server, &ca, Some(&leaf))
        .assume_role_with_certificate(None, Some(900))
        .await
        .unwrap();
    let left = credentials
        .expires
        .duration_since(std::time::SystemTime::now())
        .unwrap();
    assert!(left.as_secs() > 800 && left.as_secs() <= 900);
    let session = s3(&server, &ca, &credentials);
    let object = session
        .get_object()
        .bucket("photos")
        .key("cat.jpg")
        .send()
        .await
        .unwrap();
    assert_eq!(object.body.collect().await.unwrap().into_bytes(), "meow");
    let put = session
        .put_object()
        .bucket("photos")
        .key("dog.jpg")
        .body(ByteStream::from_static(b"woof"))
        .send()
        .await;
    assert_eq!(common::code(put), "AccessDenied");

    // Clients without a certificate still connect; they just can't sign in with one.
    let err = unsigned(&server, &ca, None)
        .assume_role_with_certificate(None, None)
        .await
        .unwrap_err();
    assert_eq!(
        refusal(&err),
        (
            400,
            "InvalidParameterValue",
            "No client certificate provided"
        )
    );
    // Signed requests still work on a connection that offered no certificate.
    root.head_bucket().bucket("photos").send().await.unwrap();

    // Another authority's certificate connects but is refused.
    let stranger = Authority::new().issue_client("readphotos");
    let err = unsigned(&server, &ca, Some(&stranger))
        .assume_role_with_certificate(None, None)
        .await
        .unwrap_err();
    assert_eq!(refusal(&err).1, "InvalidClientCertificate");

    let config = Client::new(
        &server.endpoint,
        ACCESS_KEY,
        Zeroizing::new(SECRET_KEY.to_owned()),
    )
    .unwrap()
    .with_root_certificates(ca.pem.as_bytes())
    .unwrap()
    .config()
    .await
    .unwrap();
    let shown = config.certificates.unwrap();
    assert_eq!((shown.count, shown.skip_verify), (1, false));
    assert!(shown.authorities.ends_with("CAs"), "{}", shown.authorities);
}

#[tokio::test]
async fn a_server_that_takes_no_certificates_says_so() {
    let ca = Authority::new();
    let (server, _certs) = https(&ca, None).await;
    let leaf = ca.issue_client("readphotos");
    let err = unsigned(&server, &ca, Some(&leaf))
        .assume_role_with_certificate(None, None)
        .await
        .unwrap_err();
    assert_eq!(refusal(&err).0, 503);
    assert_eq!(refusal(&err).1, "STSNotInitialized");
}

#[tokio::test]
async fn taking_certificates_needs_https_and_an_authority() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let bind = |adjust: &dyn Fn(&mut teifs_server::Config)| {
        let mut config = common::config(dir.path(), keys.path());
        adjust(&mut config);
        teifs_server::Server::bind(config)
    };
    let err = bind(&|c| c.client_certificates = Some(ClientCertificates::default()))
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("they come over HTTPS"), "{err}");

    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["127.0.0.1"]);
    let source = TlsSource::Dir(certs.path().to_owned());
    let err = bind(&|c| {
        c.tls = Some(source.clone());
        c.client_certificates = Some(ClientCertificates::default());
    })
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(
        err.contains("no authority issues them: put CA certificates in"),
        "{err}"
    );
    assert!(err.contains("CAs"), "{err}");
    // A file named instead, and a file that isn't one.
    let ca_file = certs.path().join("ca.pem");
    fs::write(&ca_file, &ca.pem).unwrap();
    let server = bind(&|c| {
        c.tls = Some(source.clone());
        c.client_certificates = Some(ClientCertificates {
            authorities: Some(ca_file.clone()),
            skip_verify: false,
        });
    })
    .await;
    assert!(server.is_ok());
    drop(server);
    fs::write(&ca_file, "not PEM").unwrap();
    let err = bind(&|c| {
        c.tls = Some(source.clone());
        c.client_certificates = Some(ClientCertificates {
            authorities: Some(ca_file.clone()),
            skip_verify: false,
        });
    })
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains("has no PEM certificate"), "{err}");
    // A path named that isn't there says so.
    let missing = certs.path().join("missing");
    let err = bind(&|c| {
        c.tls = Some(source.clone());
        c.client_certificates = Some(ClientCertificates {
            authorities: Some(missing.clone()),
            skip_verify: false,
        });
    })
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains("can't read"), "{err}");
    // Without verification, no authority is needed.
    let server = bind(&|c| {
        c.tls = Some(source.clone());
        c.client_certificates = Some(ClientCertificates {
            authorities: None,
            skip_verify: true,
        });
    })
    .await;
    assert!(server.is_ok());
}
