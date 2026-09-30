//! The audit log: one JSON line per request, with who asked what of which bucket and
//! key, how it was answered and the request id its answer carried; and never a secret.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use std::{path::Path, time::Duration};

use aws_sdk_s3::{operation::RequestId, presigning::PresigningConfig, primitives::ByteStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{ACCESS_KEY, SECRET_KEY, client, start_with};
use md5::{Digest, Md5};
use teifs_notify::testing::Receiver;
use teifs_server::AuditTarget;
use teifs_types::audit::AuditEntry;

/// The log's entries once it has at least `count`: a request is written when its answer
/// is done with, just after the client has it all.
async fn entries(log: &Path, count: usize) -> (String, Vec<AuditEntry>) {
    entries_where(log, |entries| entries.len() >= count).await
}

/// The log's entries once `done` holds for them.
async fn entries_where(
    log: &Path,
    done: impl Fn(&[AuditEntry]) -> bool,
) -> (String, Vec<AuditEntry>) {
    for _ in 0..200 {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let entries: Vec<AuditEntry> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        if done(&entries) {
            return (text, entries);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the log never had the entries awaited");
}

fn find<'e>(entries: &'e [AuditEntry], name: &str) -> &'e AuditEntry {
    entries.iter().find(|e| e.api.name == name).unwrap()
}

/// A server keeping its audit log in a folder of its own, making object buckets.
async fn audited() -> (tempfile::TempDir, std::path::PathBuf, common::Server) {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let target = AuditTarget::File(log.clone());
    let server = start_with(|config| {
        config.audit = vec![target];
        config.default_layout = teifs_store::Layout::Object;
    })
    .await;
    (dir, log, server)
}

#[tokio::test]
async fn every_request_is_a_line_without_secrets() {
    let (_dir, log, server) = audited().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("audited").send().await.unwrap();
    let key = [42u8; 32];
    let (k, m) = (STANDARD.encode(key), STANDARD.encode(Md5::digest(key)));
    let put = s3
        .put_object()
        .bucket("audited")
        .key("dir/file.txt")
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&k)
        .sse_customer_key_md5(&m)
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap();

    let (text, entries) = entries(&log, 2).await;
    let created = find(&entries, "CreateBucket");
    assert_eq!(
        (created.api.bucket.as_str(), created.api.status_code),
        ("audited", 200)
    );
    let written = find(&entries, "PutObject");
    assert_eq!(
        (
            written.version.as_str(),
            written.kind.as_str(),
            written.trigger.as_str()
        ),
        ("1", "S3", "incoming")
    );
    assert_eq!(written.request_id, put.request_id().unwrap());
    assert!(!written.deployment_id.is_empty());
    assert_eq!(
        (written.api.bucket.as_str(), written.api.object.as_str()),
        ("audited", "dir/file.txt")
    );
    assert_eq!(
        (written.api.status.as_str(), written.api.status_code),
        ("OK", 200)
    );
    assert!(written.api.rx >= 5);
    assert_eq!(written.access_key, ACCESS_KEY);
    assert_eq!(written.remote_host, "127.0.0.1");
    assert_eq!(written.request_path, "/audited/dir/file.txt");
    assert!(written.user_agent.contains("aws-sdk-rust"));
    assert!(written.api.time_to_response.ends_with("ns"));
    assert!(written.api.time_to_first_byte.ends_with("ns"));
    let rfc3339 = &time::format_description::well_known::Rfc3339;
    assert!(time::OffsetDateTime::parse(&written.time, rfc3339).is_ok());
    let header = |name: &str| written.request_header[name].as_str();
    assert_eq!(header("authorization"), "REDACTED");
    assert_eq!(
        header("x-amz-server-side-encryption-customer-key"),
        "REDACTED"
    );
    assert_eq!(header("x-amz-server-side-encryption-customer-key-md5"), m);
    assert_eq!(
        written.response_header["x-amz-request-id"],
        written.request_id
    );
    for secret in [k.as_str(), SECRET_KEY] {
        assert!(!text.contains(secret), "{secret} is in the log");
    }
}

#[tokio::test]
async fn errors_and_links_are_logged_without_their_signatures() {
    let (_dir, log, server) = audited().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("audited").send().await.unwrap();
    let missing = s3.get_object().bucket("audited").key("gone").send().await;
    assert!(missing.is_err());
    let link = s3
        .get_object()
        .bucket("audited")
        .key("gone")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    let signature = link.uri().split("X-Amz-Signature=").nth(1).unwrap();
    assert_eq!(reqwest::get(link.uri()).await.unwrap().status(), 404);

    let (text, entries) = entries(&log, 3).await;
    let failed: Vec<&AuditEntry> = entries
        .iter()
        .filter(|e| e.api.name == "GetObject")
        .collect();
    assert_eq!(failed.len(), 2);
    assert!(
        failed
            .iter()
            .all(|e| e.error == "NoSuchKey" && e.api.status_code == 404)
    );
    let linked = failed
        .iter()
        .find(|e| e.request_query.contains_key("X-Amz-Signature"))
        .unwrap();
    assert_eq!(linked.request_query["X-Amz-Signature"], "REDACTED");
    assert!(linked.request_query["X-Amz-Credential"].starts_with(ACCESS_KEY));
    assert!(
        !text.contains(signature),
        "the link's signature is in the log"
    );
}

#[tokio::test]
async fn refused_and_admin_requests_are_logged_too() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let target = AuditTarget::File(log.clone());
    let server = start_with(|config| config.audit = vec![target]).await;
    let wrong = client(&server, "not-the-secret");
    assert!(wrong.list_buckets().send().await.is_err());
    let admin = teifs_client::Client::new(
        &server.endpoint,
        ACCESS_KEY,
        teifs_client::Zeroizing::new(SECRET_KEY.into()),
    )
    .unwrap();
    admin.info().await.unwrap();
    let config = admin.config().await.unwrap();
    assert_eq!(config.audit_log, Some(log.display().to_string()));
    let (_, entries) = entries(&log, 3).await;
    let refused = find(&entries, "unknown");
    assert_eq!(refused.api.status_code, 403);
    assert_eq!(refused.error, "SignatureDoesNotMatch");
    let info = find(&entries, "GetServerInfo");
    assert_eq!(
        (info.kind.as_str(), info.access_key.as_str()),
        ("Admin", ACCESS_KEY)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// logrotate moves the file and sends `SIGHUP`: the server writes to a new one.
#[cfg(unix)]
#[tokio::test]
async fn a_hangup_reopens_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let target = AuditTarget::File(log.clone());
    let server = start_with(|config| config.audit = vec![target]).await;
    let s3 = client(&server, SECRET_KEY);
    s3.list_buckets().send().await.unwrap();
    entries(&log, 1).await;
    let rotated = dir.path().join("audit.log.1");
    std::fs::rename(&log, &rotated).unwrap();
    let hangup = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(hangup.success());
    // Until the server has reopened, entries may still go to the moved file.
    for _ in 0..200 {
        s3.list_buckets().send().await.unwrap();
        if log.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s3.head_bucket().bucket("none").send().await.unwrap_err();
    let head = |entries: &[AuditEntry]| entries.iter().any(|e| e.api.name == "HeadBucket");
    entries_where(&log, head).await;
    let (_, before) = entries(&rotated, 1).await;
    assert!(!head(&before));
}

#[tokio::test]
async fn a_log_that_cant_be_opened_stops_the_server_starting() {
    let (dir, keys) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut config = common::config(dir.path(), keys.path());
    config.audit = vec![AuditTarget::File(dir.path().join("missing/audit.log"))];
    let err = teifs_server::Server::bind(config).await.unwrap_err();
    assert!(
        err.to_string().starts_with("can't open the audit log"),
        "{err}"
    );
}

/// The entries a webhook took, once there are at least `count`.
async fn sent(receiver: &Receiver, count: usize) -> Vec<AuditEntry> {
    for _ in 0..500 {
        let entries: Vec<AuditEntry> = receiver
            .taken()
            .iter()
            .flat_map(|post| post.body.lines().map(|l| serde_json::from_str(l).unwrap()))
            .collect();
        if entries.len() >= count {
            return entries;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the webhook never had {count} entries");
}

/// A webhook that fails at first gets every entry once it takes them, as the file does,
/// with its token; and the URL is shown without its query.
#[tokio::test]
async fn a_webhook_gets_every_entry_after_failing() {
    let receiver = Receiver::start(2).await;
    let url = receiver.url().to_owned();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let hook = teifs_server::Webhook::new(
        &format!("{url}?key=secret"),
        Some(teifs_client::Zeroizing::new("t0ken".to_owned())),
    )
    .unwrap();
    let targets = vec![AuditTarget::File(log.clone()), AuditTarget::Webhook(hook)];
    let server = start_with(|config| config.audit = targets).await;
    let s3 = client(&server, SECRET_KEY);
    for n in 0..5 {
        s3.head_bucket()
            .bucket(format!("none-{n}"))
            .send()
            .await
            .unwrap_err();
    }
    let (_, written) = entries(&log, 5).await;
    let sent = sent(&receiver, 5).await;
    let ids = |entries: &[AuditEntry]| {
        entries
            .iter()
            .map(|e| e.request_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(ids(&sent), ids(&written));
    assert!(
        receiver.tries() > receiver.taken().len(),
        "it failed at first"
    );
    for post in receiver.taken() {
        assert_eq!(
            (post.authorization.as_str(), post.content_type.as_str()),
            ("Bearer t0ken", "application/x-ndjson")
        );
    }
    let admin = teifs_client::Client::new(
        &server.endpoint,
        ACCESS_KEY,
        teifs_client::Zeroizing::new(SECRET_KEY.into()),
    )
    .unwrap();
    let config = admin.config().await.unwrap();
    assert_eq!(config.audit_webhook, Some(url));
    assert_eq!(config.audit_log, Some(log.display().to_string()));
}

/// A token naming its scheme is sent as given.
#[tokio::test]
async fn a_webhook_token_with_a_scheme_is_sent_as_given() {
    let receiver = Receiver::start(0).await;
    let hook = teifs_server::Webhook::new(
        receiver.url(),
        Some(teifs_client::Zeroizing::new(
            "Basic dXNlcjpwYXNz".to_owned(),
        )),
    )
    .unwrap();
    let server = start_with(|config| config.audit = vec![AuditTarget::Webhook(hook)]).await;
    client(&server, SECRET_KEY)
        .list_buckets()
        .send()
        .await
        .unwrap();
    let sent = sent(&receiver, 1).await;
    assert_eq!(sent[0].api.name, "ListBuckets");
    assert_eq!(receiver.taken()[0].authorization, "Basic dXNlcjpwYXNz");
}
