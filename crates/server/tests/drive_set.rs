//! A drive set served over S3: objects (whole and multipart) erasure-coded across its
//! drives, still served with drives lost, and IAM kept on every drive.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use std::path::PathBuf;

use aws_sdk_s3::{
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
};
use common::{SECRET_KEY, client, restart, start_with};

/// The set's drives other than the server's own `dir`, in a folder of their own.
fn other_drives(dir: &tempfile::TempDir) -> Vec<PathBuf> {
    (1..4)
        .map(|i| {
            let drive = dir.path().join(format!("d{i}"));
            std::fs::create_dir(&drive).unwrap();
            drive
        })
        .collect()
}

fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 13 + seed) % 251).unwrap())
        .collect()
}

async fn get(s3: &aws_sdk_s3::Client, key: &str) -> Vec<u8> {
    let object = s3
        .get_object()
        .bucket("data")
        .key(key)
        .send()
        .await
        .unwrap();
    object.body.collect().await.unwrap().into_bytes().to_vec()
}

#[tokio::test]
async fn a_drive_set_serves_objects_with_drives_lost() {
    let others = tempfile::tempdir().unwrap();
    let drives = other_drives(&others);
    let set = drives.clone();
    let server = start_with(|config| config.set_drives = set).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("data").send().await.unwrap();
    let small = pattern(100, 1);
    let large = pattern((3 << 20) + 7, 2);
    s3.put_object()
        .bucket("data")
        .key("small")
        .body(ByteStream::from(small.clone()))
        .send()
        .await
        .unwrap();
    s3.put_object()
        .bucket("data")
        .key("large")
        .body(ByteStream::from(large.clone()))
        .send()
        .await
        .unwrap();
    // A multipart upload, completed into shards.
    let parts = [pattern(5 << 20, 3), pattern(1 << 20, 4)];
    let upload = s3
        .create_multipart_upload()
        .bucket("data")
        .key("multi")
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let mut done = Vec::new();
    for (n, part) in parts.iter().enumerate() {
        let number = i32::try_from(n + 1).unwrap();
        let uploaded = s3
            .upload_part()
            .bucket("data")
            .key("multi")
            .upload_id(id)
            .part_number(number)
            .body(ByteStream::from(part.clone()))
            .send()
            .await
            .unwrap();
        done.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(uploaded.e_tag().unwrap())
                .build(),
        );
    }
    s3.complete_multipart_upload()
        .bucket("data")
        .key("multi")
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(done))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let multi = parts.concat();
    assert_eq!(get(&s3, "large").await, large);
    assert_eq!(get(&s3, "multi").await, multi);
    // IAM's changes reach every drive.
    server.iam.create_user("reader", None, &[], None).unwrap();

    // Two drives lost (a 4-drive set's parity is 2), one of them the server's first.
    std::fs::remove_dir_all(&drives[0]).unwrap();
    let home = server.dir.path().to_owned();
    for entry in std::fs::read_dir(&home).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            std::fs::remove_dir_all(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }
    let set = drives.clone();
    let server = restart(server, |config| config.set_drives = set).await;
    let s3 = client(&server, SECRET_KEY);
    assert_eq!(get(&s3, "small").await, small);
    assert_eq!(get(&s3, "large").await, large);
    assert_eq!(get(&s3, "multi").await, multi);
    let listed = s3.list_objects_v2().bucket("data").send().await.unwrap();
    let keys: Vec<_> = listed.contents().iter().filter_map(|o| o.key()).collect();
    assert_eq!(keys, ["large", "multi", "small"]);
    assert!(server.iam.user("reader").is_ok());
    // Writes need three drives: refused with a 503 the SDK can retry later.
    let refused = s3
        .put_object()
        .bucket("data")
        .key("new")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        refused.raw_response().unwrap().status().as_u16(),
        503,
        "{refused:?}"
    );
}
