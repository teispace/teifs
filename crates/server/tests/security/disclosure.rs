//! Class 13: authorization comes before anything that looks at the object, so whoever
//! may not read it learns nothing about it.
//!
//! Also proved elsewhere: a missing key is `AccessDenied` to whoever may not list the
//! bucket, `NoSuchKey` to whoever may (`iam.rs`, `missing_keys_are_hidden_from_those_who_cant_list`).

use aws_sdk_s3::primitives::ByteStream;

use crate::{
    common::{SECRET_KEY, Server, client, start},
    sign::{Answer, Payload, signed},
};

/// Asks as `key`, or anonymously.
async fn ask(
    server: &Server,
    key: Option<(&str, &str)>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Answer {
    if let Some(key) = key {
        return signed(server, key, method, path, headers, Payload::Bytes(b""))
            .send(&[], "")
            .await;
    }
    let mut request = reqwest::Client::new().request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        format!("{}{path}", server.endpoint),
    );
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    Answer::from(request.send().await.unwrap()).await
}

/// A request: method, path and headers.
type Ask<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>);

/// CVE-2024-36107 (MinIO: a conditional read was answered `304 Not Modified` before
/// access was checked, telling anyone an object's ETag and dates): refused callers get
/// the same `403` however they ask, with nothing of the object in it.
#[tokio::test]
async fn refused_reads_reveal_nothing_whatever_they_ask() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("private").send().await.unwrap();
    let put = root
        .put_object()
        .bucket("private")
        .key("doc")
        .metadata("owner", "alice-in-finance")
        .body(ByteStream::from_static(b"the quarterly numbers"))
        .send()
        .await
        .unwrap();
    let etag = put.e_tag().unwrap().to_owned();
    server.iam.create_user("nobody", None, &[], None).unwrap();
    let key = server.iam.create_access_key("nobody").unwrap();
    let nobody = (key.info.id.as_str(), key.secret.as_str());

    let asks: [Ask<'_>; 11] = [
        ("GET", "/private/doc", vec![("if-none-match", &etag)]),
        ("GET", "/private/doc", vec![("if-match", "\"wrong\"")]),
        (
            "GET",
            "/private/doc",
            vec![("if-modified-since", "Sat, 01 Jan 2033 00:00:00 GMT")],
        ),
        (
            "GET",
            "/private/doc",
            vec![("if-unmodified-since", "Mon, 01 Jan 1990 00:00:00 GMT")],
        ),
        ("GET", "/private/doc", vec![("range", "bytes=5000-6000")]),
        ("GET", "/private/doc?partNumber=3", vec![]),
        ("HEAD", "/private/doc", vec![("if-none-match", &etag)]),
        ("HEAD", "/private/doc", vec![]),
        ("GET", "/private/doc?tagging", vec![]),
        (
            "GET",
            "/private/doc?attributes",
            vec![("x-amz-object-attributes", "ETag,ObjectSize")],
        ),
        ("GET", "/private/missing", vec![("if-none-match", "*")]),
    ];
    for who in [Some(nobody), None] {
        for (method, path, headers) in &asks {
            let answer = ask(&server, who, method, path, headers).await;
            let what = format!("{method} {path} {headers:?} as {who:?}");
            assert_eq!(answer.status, 403, "{what}: {}", answer.body);
            if *method == "GET" {
                assert_eq!(answer.code, "AccessDenied", "{what}");
            }
            for header in [
                "etag",
                "last-modified",
                "x-amz-meta-owner",
                "content-range",
                "x-amz-version-id",
            ] {
                assert!(!answer.headers.contains_key(header), "{what}: {header}");
            }
            for secret in [etag.trim_matches('"'), "alice-in-finance", "quarterly"] {
                assert!(!answer.body.contains(secret), "{what}: {}", answer.body);
            }
        }
    }
    // Allowed, the same questions get their real answers.
    let root_key = (crate::common::ACCESS_KEY, SECRET_KEY);
    let answer = ask(
        &server,
        Some(root_key),
        "GET",
        "/private/doc",
        &[("if-none-match", &etag)],
    )
    .await;
    assert_eq!(answer.status, 304);
}
