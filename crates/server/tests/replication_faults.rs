//! Replication to a target that fails as targets do: refusing for good (`4xx`, `501`),
//! busy (`5xx`, `408`, `429`), gone mid-request (a dropped connection, a body cut
//! short), for each kind of thing sent (versions small and in parts, delete markers,
//! removals, metadata changes). What's refused fails once and stays failed; everything
//! else gets there whole once the target is back, and a cut request leaves nothing.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{
        BucketVersioningStatus, CompletedMultipartUpload, CompletedPart, ReplicationStatus, Tag,
        Tagging, VersioningConfiguration,
    },
};
use common::{
    ACCESS_KEY, SECRET_KEY, Server, client,
    faulty::{Answer, Faulty},
    start_with,
};
use teifs_client::{NewReplicationTarget, Zeroizing};
use teifs_store::Layout;

const MIB: usize = 1024 * 1024;

/// The source's server, the target's, the proxy in front of the target, and clients
/// for the source and the target.
struct Setup {
    _servers: (Server, Server),
    faulty: Faulty,
    source: Client,
    copy: Client,
}

async fn versioned(s3: &Client, bucket: &str) {
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
}

/// `source` on one server replicating everything (removals too) to `copy` on another,
/// reached through the proxy.
async fn setup() -> Setup {
    let object = |c: &mut teifs_server::Config| c.default_layout = Layout::Object;
    let (from, to) = (start_with(object).await, start_with(object).await);
    let (source, copy) = (client(&from, SECRET_KEY), client(&to, SECRET_KEY));
    versioned(&source, "source").await;
    versioned(&copy, "copy").await;
    let faulty = Faulty::new(&to.endpoint).await;
    let admin = teifs_client::Client::new(
        &from.endpoint,
        ACCESS_KEY,
        Zeroizing::new(SECRET_KEY.to_owned()),
    )
    .unwrap();
    let arn = admin
        .add_replication_target(
            "source",
            &NewReplicationTarget {
                endpoint: &faulty.address,
                secure: false,
                bucket: "copy",
                region: "",
                access_key: ACCESS_KEY,
                secret_key: SECRET_KEY,
                session_token: None,
                storage_class: "",
                bandwidth_limit: 0,
                sync: false,
            },
        )
        .await
        .unwrap();
    let rules = format!(
        "<ReplicationConfiguration><Role></Role><Rule><ID>r</ID><Status>Enabled</Status>\
         <Priority>1</Priority><DeleteMarkerReplication><Status>Enabled</Status>\
         </DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status>\
         </DeleteReplication><Filter><Prefix></Prefix></Filter>\
         <Destination><Bucket>{arn}</Bucket></Destination></Rule>\
         </ReplicationConfiguration>"
    );
    admin
        .set_bucket_replication("source", rules.into_bytes())
        .await
        .unwrap();
    Setup {
        _servers: (from, to),
        faulty,
        source,
        copy,
    }
}

impl Setup {
    async fn put(&self, key: &str, body: &[u8]) -> String {
        self.source
            .put_object()
            .bucket("source")
            .key(key)
            .body(ByteStream::from(body.to_vec()))
            .send()
            .await
            .unwrap()
            .version_id
            .unwrap()
    }

    /// Wakes the replication job with a write of its own.
    async fn nudge(&self) {
        self.put("nudge", b"").await;
    }

    async fn status(&self, key: &str) -> Option<ReplicationStatus> {
        self.source
            .head_object()
            .bucket("source")
            .key(key)
            .send()
            .await
            .unwrap()
            .replication_status
    }

    /// `key`'s status once it isn't pending, waking the job now and then.
    async fn settled(&self, key: &str) -> Option<ReplicationStatus> {
        for round in 0..600 {
            let status = self.status(key).await;
            if status != Some(ReplicationStatus::Pending) {
                return status;
            }
            if round % 10 == 9 {
                self.nudge().await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        Some(ReplicationStatus::Pending)
    }

    /// Waits, waking the job now and then, until `done` says the copy is as it should be.
    async fn until<F: AsyncFn(&Client) -> bool>(&self, done: F) {
        for round in 0..600 {
            if done(&self.copy).await {
                return;
            }
            if round % 10 == 9 {
                self.nudge().await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the copy never got there");
    }

    async fn copy_body(&self, key: &str) -> Option<Vec<u8>> {
        let got = self
            .copy
            .get_object()
            .bucket("copy")
            .key(key)
            .send()
            .await
            .ok()?;
        Some(got.body.collect().await.unwrap().into_bytes().to_vec())
    }

    /// `key`'s ETag on the source and on the copy.
    async fn etags(&self, key: &str) -> (Option<String>, Option<String>) {
        let source = self.source.head_object().bucket("source").key(key);
        let copy = self.copy.head_object().bucket("copy").key(key);
        (
            source.send().await.unwrap().e_tag,
            copy.send().await.unwrap().e_tag,
        )
    }

    async fn copy_versions(&self, key: &str) -> (usize, usize) {
        let listed = self
            .copy
            .list_object_versions()
            .bucket("copy")
            .prefix(key)
            .send()
            .await
            .unwrap();
        (listed.versions().len(), listed.delete_markers().len())
    }
}

#[tokio::test]
async fn a_version_the_target_refuses_fails_once_and_stays_failed() {
    let setup = setup().await;
    for (key, answer) in [
        ("k-denied", Answer::Status(403, "AccessDenied")),
        ("k-nobucket", Answer::Status(404, "NoSuchBucket")),
        ("k-unsupported", Answer::Status(501, "NotImplemented")),
    ] {
        setup
            .faulty
            .fail("PUT", &format!("/copy/{key}"), answer, usize::MAX);
        setup.put(key, b"refused").await;
        assert_eq!(
            setup.settled(key).await,
            Some(ReplicationStatus::Failed),
            "{key}"
        );
        for _ in 0..3 {
            setup.nudge().await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            setup.faulty.count("PUT", &format!("/copy/{key}")),
            1,
            "{key}"
        );
        assert_eq!(setup.status(key).await, Some(ReplicationStatus::Failed));
        assert_eq!(setup.copy_versions(key).await, (0, 0));
    }
}

#[tokio::test]
async fn a_version_reaches_a_busy_or_unreachable_target_once_it_answers() {
    let setup = setup().await;
    for (key, answer) in [
        ("k-500", Answer::Status(500, "InternalError")),
        ("k-503", Answer::Status(503, "SlowDown")),
        ("k-408", Answer::Status(408, "RequestTimeout")),
        ("k-429", Answer::Status(429, "TooManyRequests")),
        ("k-drop", Answer::Drop),
        ("k-cut", Answer::Cut),
    ] {
        let target = format!("/copy/{key}");
        setup.faulty.fail("PUT", &target, answer, 2);
        let body = format!("{key} arrived whole").into_bytes();
        let id = setup.put(key, &body).await;
        assert_eq!(
            setup.settled(key).await,
            Some(ReplicationStatus::Completed),
            "{key}"
        );
        assert_eq!(setup.faulty.count("PUT", &target), 3, "{key}");
        assert_eq!(setup.copy_body(key).await, Some(body), "{key}");
        // One version, with the source's id: a cut request left nothing behind.
        assert_eq!(setup.copy_versions(key).await, (1, 0), "{key}");
        let head = setup
            .copy
            .head_object()
            .bucket("copy")
            .key(key)
            .send()
            .await
            .unwrap();
        assert_eq!(head.version_id, Some(id));
        assert_eq!(head.replication_status, Some(ReplicationStatus::Replica));
    }
}

#[tokio::test]
async fn a_version_in_parts_gets_there_whole_and_leaves_no_upload() {
    let setup = setup().await;
    let body: Vec<u8> = (0..5 * MIB + 7)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let upload = setup
        .source
        .create_multipart_upload()
        .bucket("source")
        .key("k-parts")
        .send()
        .await
        .unwrap();
    let upload_id = upload.upload_id.unwrap();
    let mut parts = Vec::new();
    for (number, chunk) in (1..).zip(body.chunks(5 * MIB)) {
        let part = setup
            .source
            .upload_part()
            .bucket("source")
            .key("k-parts")
            .upload_id(&upload_id)
            .part_number(number)
            .body(ByteStream::from(chunk.to_vec()))
            .send()
            .await
            .unwrap();
        parts.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(part.e_tag.unwrap())
                .build(),
        );
    }
    // The second part fails, then the connection drops as the upload completes, then the
    // first part is cut short.
    setup.faulty.fail(
        "PUT",
        "k-parts?x-id=UploadPart&partNumber=2&",
        Answer::Status(500, "InternalError"),
        1,
    );
    setup
        .faulty
        .fail("POST", "k-parts?uploadId", Answer::Drop, 1);
    setup.faulty.fail(
        "PUT",
        "k-parts?x-id=UploadPart&partNumber=1&",
        Answer::Cut,
        1,
    );
    setup
        .source
        .complete_multipart_upload()
        .bucket("source")
        .key("k-parts")
        .upload_id(&upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        setup.settled("k-parts").await,
        Some(ReplicationStatus::Completed)
    );
    assert_eq!(setup.copy_body("k-parts").await, Some(body));
    assert_eq!(setup.copy_versions("k-parts").await, (1, 0));
    let (source_etag, copy_etag) = setup.etags("k-parts").await;
    assert_eq!(copy_etag, source_etag);
    // Each failed attempt's upload was aborted.
    assert_eq!(
        setup
            .faulty
            .count("DELETE", "k-parts?x-id=AbortMultipartUpload"),
        3
    );
    assert_eq!(setup.faulty.unspent(), []);
    // Uploads the failed attempts started don't stay on the target.
    let uploads = setup
        .copy
        .list_multipart_uploads()
        .bucket("copy")
        .send()
        .await
        .unwrap();
    assert!(uploads.uploads().is_empty(), "{:?}", uploads.uploads());
}

#[tokio::test]
async fn markers_removals_and_changes_wait_for_the_target() {
    let setup = setup().await;
    let id = setup.put("k-gone", b"first").await;
    setup.put("k-marked", b"marked").await;
    setup.put("k-tagged", b"tagged").await;
    for key in ["k-gone", "k-marked", "k-tagged"] {
        assert_eq!(setup.settled(key).await, Some(ReplicationStatus::Completed));
    }
    // A delete marker, a removed version and changed tags, each failing twice first.
    setup.faulty.fail(
        "DELETE",
        "/copy/k-marked",
        Answer::Status(503, "SlowDown"),
        2,
    );
    setup.faulty.fail("DELETE", "/copy/k-gone", Answer::Drop, 2);
    setup.faulty.fail(
        "PUT",
        "/copy/k-tagged",
        Answer::Status(500, "InternalError"),
        2,
    );
    setup
        .source
        .delete_object()
        .bucket("source")
        .key("k-marked")
        .send()
        .await
        .unwrap();
    setup
        .source
        .delete_object()
        .bucket("source")
        .key("k-gone")
        .version_id(&id)
        .send()
        .await
        .unwrap();
    setup
        .source
        .put_object_tagging()
        .bucket("source")
        .key("k-tagged")
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("kept").value("yes").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    setup
        .until(async |copy: &Client| {
            let listed = copy
                .list_object_versions()
                .bucket("copy")
                .prefix("k-marked")
                .send()
                .await
                .unwrap();
            listed.delete_markers().len() == 1
        })
        .await;
    setup
        .until(async |copy: &Client| {
            let listed = copy
                .list_object_versions()
                .bucket("copy")
                .prefix("k-gone")
                .send()
                .await
                .unwrap();
            listed.versions().is_empty()
        })
        .await;
    setup
        .until(async |copy: &Client| {
            let tags = copy
                .get_object_tagging()
                .bucket("copy")
                .key("k-tagged")
                .send()
                .await
                .unwrap();
            tags.tag_set().iter().any(|t| t.key() == "kept")
        })
        .await;
    assert_eq!(setup.copy_versions("k-tagged").await, (1, 0));
    assert!(setup.faulty.count("DELETE", "/copy/k-marked") >= 3);
    assert!(setup.faulty.count("DELETE", "/copy/k-gone") >= 3);
    assert_eq!(setup.faulty.unspent(), []);
}
