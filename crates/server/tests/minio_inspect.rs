//! `MinIO`'s `inspect-data` (`mc support inspect`): what the drive keeps about the
//! objects a pattern names, zipped and sealed for support.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::io::Read as _;

use aws_sdk_s3::{
    primitives::ByteStream,
    types::{BucketVersioningStatus, VersioningConfiguration},
};
use serde_json::Value;

mod common;
mod signing;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, start_with, user};
use signing::{signed, signed_response};

const ROOT: (&str, &str) = (ACCESS_KEY, SECRET_KEY);

/// The files of a format 1 download, by name.
async fn inspect(server: &Server, query: &str) -> Vec<(String, Vec<u8>)> {
    let path = format!("/minio/admin/v3/inspect-data?{query}");
    let response = signed_response(server, ROOT, "GET", &path, &[], &[]).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    let download = response.bytes().await.unwrap();
    assert_eq!(download[0], 1, "format 1: the key comes first");
    let zip = teifs_crypto::inspect::open_with_key(&download).unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip.to_vec())).unwrap();
    (0..archive.len())
        .map(|i| {
            let mut file = archive.by_index(i).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            (file.name().to_owned(), bytes)
        })
        .collect()
}

/// The records in a download, by key.
fn records(files: &[(String, Vec<u8>)]) -> Vec<(String, Value)> {
    files
        .iter()
        .filter(|(name, _)| name.ends_with("/teifs.meta.json"))
        .map(|(_, bytes)| {
            let records: Value = serde_json::from_slice(bytes).unwrap();
            (records["key"].as_str().unwrap().to_owned(), records)
        })
        .collect()
}

async fn put(server: &Server, bucket: &str, key: &str, body: &'static str) {
    client(server, SECRET_KEY)
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(body.as_bytes()))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn mc_support_inspect_gets_the_records_a_pattern_names() {
    let server = start_with(|c| c.default_layout = teifs_store::Layout::Object).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("photos").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("photos")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    put(&server, "photos", "a.jpg", "first").await;
    put(&server, "photos", "a.jpg", "second").await;
    put(&server, "photos", "b.jpg", "bee").await;
    put(&server, "photos", "dir/c.txt", "sea").await;

    // `MinIO`'s usual path names the key through its `xl.meta`.
    let files = inspect(&server, "volume=photos&file=a.jpg/xl.meta").await;
    let (input, text) = &files[0];
    assert_eq!(input, "inspect-input.txt");
    let text = String::from_utf8_lossy(text);
    assert!(
        text.starts_with("Inspect path: photos/a.jpg/xl.meta\n"),
        "{text}"
    );
    let node = server.endpoint.trim_start_matches("http://");
    let name = &files[1].0;
    assert!(
        name.starts_with(&format!("{node}/")) && name.ends_with("/photos/a.jpg/teifs.meta.json"),
        "{name}"
    );
    let records = records(&files);
    assert_eq!(records.len(), 1);
    let a = &records[0].1;
    assert_eq!(a["layout"], "object");
    let versions = a["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["latest"], true);
    assert_eq!(versions[0]["size"], 6);
    assert_eq!(versions[1]["latest"], false);
    // The bytes themselves stay out.
    assert!(!String::from_utf8_lossy(&files[1].1).contains("second"));
    let format = files.last().unwrap();
    assert!(format.0.ends_with("/.teifs/format.json"), "{}", format.0);
    let format: Value = serde_json::from_slice(&format.1).unwrap();
    assert!(format["format"].as_u64().is_some());

    // Within a name, across names.
    let keys = |files: &[(String, Vec<u8>)]| -> Vec<String> {
        self::records(files).into_iter().map(|(k, _)| k).collect()
    };
    let files = inspect(&server, "volume=photos&file=*.jpg").await;
    assert_eq!(keys(&files), ["a.jpg", "b.jpg"]);
    let files = inspect(&server, "volume=photos&file=**").await;
    assert_eq!(keys(&files), ["a.jpg", "b.jpg", "dir/c.txt"]);
    let files = inspect(&server, "volume=photos&file=dir/*/xl.meta").await;
    assert_eq!(keys(&files), ["dir/c.txt"]);

    // Nothing matched, or no such bucket: what was asked alone, as on `MinIO`.
    for query in ["volume=photos&file=nothing*", "volume=missing&file=a.jpg"] {
        let files = inspect(&server, query).await;
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["inspect-input.txt"], "{query}");
    }

    // The drive's format.json, by `MinIO`'s name for its system volume.
    let files = inspect(&server, "volume=.minio.sys&file=format.json").await;
    assert_eq!(files.len(), 2);
    assert!(files[1].0.ends_with("/.teifs/format.json"));
}

#[tokio::test]
async fn a_folder_bucket_s_file_row_is_included() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("docs").send().await.unwrap();
    put(&server, "docs", "notes/today.txt", "hello").await;
    let files = inspect(&server, "volume=docs&file=notes/today.txt").await;
    let records = records(&files);
    let notes = &records[0].1;
    assert_eq!(notes["layout"], "folder");
    assert_eq!(notes["file"]["size"], 5);
    assert!(notes["versions"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_public_key_seals_the_download_for_its_private_key() {
    use aws_lc_rs::{
        encoding::AsDer as _,
        rsa::{KeySize, PrivateDecryptingKey},
    };
    let server = start().await;
    client(&server, SECRET_KEY)
        .create_bucket()
        .bucket("docs")
        .send()
        .await
        .unwrap();
    put(&server, "docs", "a.txt", "hello").await;
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    let spki = private.public_key().as_der().unwrap();
    // A 2048-bit key's `SubjectPublicKeyInfo` ends in its PKCS #1 form.
    let pkcs1 = &spki.as_ref()[24..];
    assert_eq!(pkcs1[0], 0x30);
    let b64 =
        |bytes: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    // The characters base64 and the bad key below have that a form escapes.
    let form = |key: &str| {
        let key = key
            .replace('%', "%25")
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        format!("volume=docs&file=a.txt&public-key={key}")
    };
    let headers = [("content-type", "application/x-www-form-urlencoded")];
    let path = "/minio/admin/v3/inspect-data";
    let response = signed_response(
        &server,
        ROOT,
        "POST",
        path,
        &headers,
        form(&b64(pkcs1)).as_bytes(),
    )
    .await;
    assert_eq!(response.status(), 200);
    let download = response.bytes().await.unwrap();
    assert_eq!(download[..2], [2, 1], "estream 2.1");
    // The key it was sealed for, repeated so the caller finds its own.
    assert!(download.windows(pkcs1.len()).any(|w| w == pkcs1));

    // Not a PKCS #1 key (here, the `SubjectPublicKeyInfo`), and not base64.
    for key in [b64(spki.as_ref()), "%%%".to_owned()] {
        let (status, text) =
            signed(&server, ROOT, "POST", path, &headers, form(&key).as_bytes()).await;
        assert_eq!(status, 400, "{text}");
        assert!(text.contains("XMinioAdminInvalidArgument"), "{text}");
    }
}

#[tokio::test]
async fn bad_requests_and_callers_without_the_action_are_refused() {
    let server = start().await;
    for (query, code) in [
        ("file=a", "InvalidBucketName"),
        ("volume=docs", "InvalidRequest"),
        ("volume=docs&file=../x", "XMinioInvalidResourceName"),
        ("volume=..&file=x", "XMinioInvalidResourceName"),
    ] {
        let path = format!("/minio/admin/v3/inspect-data?{query}");
        let (status, text) = signed(&server, ROOT, "GET", &path, &[], &[]).await;
        assert_eq!(status, 400, "{query}: {text}");
        assert!(text.contains(code), "{query}: {text}");
    }
    let reader = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"admin:OBDInfo","Resource":"*"}]}"#;
    user(&server, "alice", Some(reader));
    let key = server.iam.create_access_key("alice").unwrap();
    let alice = (key.info.id.as_str(), key.secret.as_str());
    let path = "/minio/admin/v3/inspect-data?volume=docs&file=a";
    assert_eq!(signed(&server, alice, "GET", path, &[], &[]).await.0, 403);
}
