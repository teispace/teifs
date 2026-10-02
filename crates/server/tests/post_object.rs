//! Browser uploads: `POST` with a form, signed as a web app signs AWS's POST policies
//! (Signature V4), or not signed at all. The form's policy says what may be sent, and the
//! signer's IAM policies and the bucket's decide the object the form names.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::primitives::ByteStream;
use base64::Engine;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, start_with};

const FAR: &str = "2099-01-01T00:00:00Z";
const BOUNDARY: &str = "----teifs-form-boundary";

/// `YYYYMMDD` and `YYYYMMDDTHHMMSSZ` for now, as Signature V4 writes them.
fn dates(now: SystemTime) -> (String, String) {
    let secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days = i64::try_from(secs / 86_400).unwrap();
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let date = format!("{year:04}{month:02}{day:02}");
    let time = secs % 86_400;
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        time / 3_600,
        time / 60 % 60,
        time % 60
    );
    (date, stamp)
}

/// A form's fields, signed by `(access key, secret)`: `fields`, and a policy with
/// `conditions` and those the signature's own fields need.
fn signed(
    key: (&str, &str),
    expiration: &str,
    conditions: &[Value],
    fields: &[(&str, &str)],
) -> Vec<(String, String)> {
    signed_at(key, SystemTime::now(), expiration, conditions, fields)
}

/// [`signed`] as of `now`.
fn signed_at(
    (access_key, secret): (&str, &str),
    now: SystemTime,
    expiration: &str,
    conditions: &[Value],
    fields: &[(&str, &str)],
) -> Vec<(String, String)> {
    let (date, stamp) = dates(now);
    let credential = format!("{access_key}/{date}/us-east-1/s3/aws4_request");
    let mut all = conditions.to_vec();
    all.extend([
        json!({"x-amz-algorithm": "AWS4-HMAC-SHA256"}),
        json!({"x-amz-credential": credential}),
        json!({"x-amz-date": stamp}),
    ]);
    let policy = base64::engine::general_purpose::STANDARD
        .encode(json!({"expiration": expiration, "conditions": all}).to_string());
    let key = aws_sigv4::sign::v4::generate_signing_key(secret, now, "us-east-1", "s3");
    let signature = aws_sigv4::sign::v4::calculate_signature(key, policy.as_bytes());
    let mut out: Vec<(String, String)> = fields
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    out.extend([
        ("x-amz-algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()),
        ("x-amz-credential".to_owned(), credential),
        ("x-amz-date".to_owned(), stamp),
        ("policy".to_owned(), policy),
        ("x-amz-signature".to_owned(), signature),
    ]);
    out
}

/// A root-signed form for `bucket` with any key under `prefix`, and `fields`.
fn root_form(bucket: &str, extra: &[Value], fields: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut conditions = vec![
        json!({"bucket": bucket}),
        json!(["starts-with", "$key", ""]),
    ];
    conditions.extend_from_slice(extra);
    signed((ACCESS_KEY, SECRET_KEY), FAR, &conditions, fields)
}

/// A multipart form body: `fields`, then the file.
fn body(fields: &[(String, String)], file_name: &str, file: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// What a form post was answered.
struct Answer {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }
}

/// Posts a form to `bucket`.
async fn post(server: &Server, bucket: &str, fields: &[(String, String)], file: &[u8]) -> Answer {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(format!("{}/{bucket}", server.endpoint))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body(fields, "photo.jpg", file))
        .send()
        .await
        .unwrap();
    Answer {
        status: response.status().as_u16(),
        headers: response.headers().clone(),
        body: response.text().await.unwrap(),
    }
}

async fn read(server: &Server, bucket: &str, key: &str) -> Vec<u8> {
    let object = client(server, SECRET_KEY)
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap();
    object.body.collect().await.unwrap().to_vec()
}

async fn bucket(server: &Server, name: &str) {
    client(server, SECRET_KEY)
        .create_bucket()
        .bucket(name)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn a_signed_form_uploads_what_it_says() {
    let server = start().await;
    bucket(&server, "photos").await;
    let form = root_form(
        "photos",
        &[
            json!(["starts-with", "$Content-Type", "image/"]),
            json!(["starts-with", "$x-amz-meta-album", ""]),
        ],
        &[
            ("key", "uploads/${filename}"),
            ("Content-Type", "image/jpeg"),
            ("x-amz-meta-album", "summer"),
        ],
    );
    let answer = post(&server, "photos", &form, b"jpeg bytes").await;
    assert_eq!(answer.status, 204);
    assert_eq!(
        answer.header("etag"),
        Some(r#""2ccd799f3a5130350478899447b6aa06""#)
    );
    assert_eq!(
        read(&server, "photos", "uploads/photo.jpg").await,
        b"jpeg bytes"
    );
    let head = client(&server, SECRET_KEY)
        .head_object()
        .bucket("photos")
        .key("uploads/photo.jpg")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_type(), Some("image/jpeg"));
    assert_eq!(head.metadata().unwrap()["album"], "summer");
    // `success_action_status` 201 answers where the object is.
    let form = root_form(
        "photos",
        &[json!({"success_action_status": "201"})],
        &[("key", "a.txt"), ("success_action_status", "201")],
    );
    let Answer { status, body, .. } = post(&server, "photos", &form, b"a").await;
    assert_eq!(status, 201);
    let etag = "<ETag>&quot;0cc175b9c0f1b6a831c399e269772661&quot;</ETag>";
    assert!(
        body.contains("<Key>a.txt</Key>")
            && body.contains("<Bucket>photos</Bucket>")
            && body.contains(etag),
        "{body}"
    );
    // A redirect goes back to the page, with the object's bucket, key and ETag.
    let form = root_form(
        "photos",
        &[json!({"success_action_redirect": "https://app.example/done?x=1"})],
        &[
            ("key", "b.txt"),
            ("success_action_redirect", "https://app.example/done?x=1"),
        ],
    );
    let answer = post(&server, "photos", &form, b"b").await;
    assert_eq!(answer.status, 303);
    assert_eq!(
        answer.header("location").unwrap(),
        "https://app.example/done?x=1&bucket=photos&key=b.txt&etag=%2292eb5ffee6ae2fec3ad71c777531578f%22"
    );
}

#[tokio::test]
async fn the_forms_acl_and_tags_are_applied() {
    let server = start_with(|config| config.legacy_bucket_defaults = true).await;
    bucket(&server, "site").await;
    let tagging =
        "<Tagging><TagSet><Tag><Key>team</Key><Value>web app</Value></Tag></TagSet></Tagging>";
    let form = root_form(
        "site",
        &[json!({"acl": "public-read"}), json!({"tagging": tagging})],
        &[
            ("key", "index.html"),
            ("acl", "public-read"),
            ("tagging", tagging),
        ],
    );
    let Answer { status, body, .. } = post(&server, "site", &form, b"<html>").await;
    assert_eq!(status, 204, "{body}");
    let tags = client(&server, SECRET_KEY)
        .get_object_tagging()
        .bucket("site")
        .key("index.html")
        .send()
        .await
        .unwrap();
    let tag = &tags.tag_set()[0];
    assert_eq!((tag.key(), tag.value()), ("team", "web app"));
    assert_eq!(
        common::anonymous(&server, reqwest::Method::GET, "/site/index.html").await,
        200
    );
    // A tag set that isn't one.
    let form = root_form(
        "site",
        &[json!({"tagging": "<Tagging>"})],
        &[("key", "x"), ("tagging", "<Tagging>")],
    );
    let Answer { status, body, .. } = post(&server, "site", &form, b"x").await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("MalformedXML"), "{body}");

    // A bucket with ACLs disabled, as AWS makes them now, refuses a public ACL.
    let server = start().await;
    bucket(&server, "site").await;
    let form = root_form(
        "site",
        &[json!({"acl": "public-read"})],
        &[("key", "index.html"), ("acl", "public-read")],
    );
    let Answer { status, body, .. } = post(&server, "site", &form, b"<html>").await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("AccessControlListNotSupported"), "{body}");
}

#[tokio::test]
async fn the_policy_decides_what_may_be_sent() {
    let server = start().await;
    bucket(&server, "photos").await;
    let refused = |form: Vec<(String, String)>, status: u16, code: &'static str| {
        let server = &server;
        async move {
            let Answer {
                status: got, body, ..
            } = post(server, "photos", &form, b"12345").await;
            assert_eq!(got, status, "{body}");
            assert!(body.contains(code), "{code}: {body}");
        }
    };
    let under = |prefix: &str| json!(["starts-with", "$key", prefix]);
    let fields = [("key", "private/x")];
    // A key the policy doesn't allow, a field it doesn't name, a size it doesn't allow.
    let form = signed(
        (ACCESS_KEY, SECRET_KEY),
        FAR,
        &[json!({"bucket": "photos"}), under("uploads/")],
        &fields,
    );
    refused(form, 403, "AccessDenied").await;
    let form = root_form("photos", &[], &[("key", "a"), ("x-amz-meta-extra", "1")]);
    refused(form, 403, "AccessDenied").await;
    let form = root_form(
        "photos",
        &[json!(["content-length-range", 0, 4])],
        &[("key", "a")],
    );
    refused(form, 400, "EntityTooLarge").await;
    // Another bucket's form, an expired one, and a wrong signature.
    let form = root_form("other", &[], &[("key", "a")]);
    refused(form, 403, "AccessDenied").await;
    // What the refusal quotes is escaped.
    let form = root_form(
        "photos",
        &[json!({"x-amz-meta-a": "<b>"})],
        &[("key", "a"), ("x-amz-meta-a", "c")],
    );
    refused(form, 403, "&lt;b&gt;").await;
    // A policy that isn't one.
    let mut form = root_form("photos", &[], &[("key", "a")]);
    for (name, value) in &mut form {
        if name == "policy" {
            *value = base64::engine::general_purpose::STANDARD.encode("{\"conditions\": 1}");
        }
    }
    refused(form, 400, "InvalidPolicyDocument").await;
    let form = signed(
        (ACCESS_KEY, SECRET_KEY),
        "2000-01-01T00:00:00Z",
        &[json!({"bucket": "photos"}), under("")],
        &[("key", "a")],
    );
    refused(form, 403, "AccessDenied").await;
    let form = signed(
        (ACCESS_KEY, "not-the-secret"),
        FAR,
        &[json!({"bucket": "photos"}), under("")],
        &[("key", "a")],
    );
    refused(form, 403, "SignatureDoesNotMatch").await;
    // Expirations AWS wouldn't read: only UTC, written with a `Z`.
    for expiration in ["2099-01-01 00:00:00", "2099-01-01T00:00:00+01:00"] {
        let form = signed(
            (ACCESS_KEY, SECRET_KEY),
            expiration,
            &[json!({"bucket": "photos"}), under("")],
            &[("key", "a")],
        );
        refused(form, 400, "InvalidPolicyDocument").await;
    }
    // A form with a policy but without its signature isn't taken as anonymous.
    let mut form = root_form("photos", &[], &[("key", "a")]);
    form.retain(|(name, _)| name != "x-amz-signature");
    refused(form, 400, "X-Amz-Signature").await;
    // Nothing of it was written.
    let listed = client(&server, SECRET_KEY)
        .list_objects_v2()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.key_count(), Some(0));
}

#[tokio::test]
async fn users_upload_only_where_their_policies_allow() {
    let server = start().await;
    bucket(&server, "photos").await;
    server.iam.create_user("web", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::User("web"),
            "uploads",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject",
                "Resource":"arn:aws:s3:::photos/uploads/*",
                "Condition":{"StringEquals":{"s3:authType":"POST","s3:signatureversion":"AWS4-HMAC-SHA256"}}}]}"#,
        )
        .unwrap();
    let key = server.iam.create_access_key("web").unwrap();
    let web = (key.info.id.as_str(), key.secret.as_str());
    let form = |key: &str, extra: &[(&str, &str)], conditions: &[Value]| {
        let mut all = vec![
            json!({"bucket": "photos"}),
            json!(["starts-with", "$key", ""]),
        ];
        all.extend_from_slice(conditions);
        let mut fields = vec![("key", key)];
        fields.extend_from_slice(extra);
        signed(web, FAR, &all, &fields)
    };
    let Answer { status, body, .. } =
        post(&server, "photos", &form("uploads/a.jpg", &[], &[]), b"a").await;
    assert_eq!(status, 204, "{body}");
    // The key the form names decides, whatever its policy allows.
    let Answer { status, body, .. } =
        post(&server, "photos", &form("elsewhere.jpg", &[], &[]), b"a").await;
    assert_eq!(status, 403, "{body}");
    let Answer { status, .. } = post(&server, "photos", &form("${filename}", &[], &[]), b"a").await;
    assert_eq!(status, 403);
    // Tags need s3:PutObjectTagging too.
    let tagging = "<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
    let tagged = form(
        "uploads/t.jpg",
        &[("tagging", tagging)],
        &[json!({"tagging": tagging})],
    );
    let Answer { status, body, .. } = post(&server, "photos", &tagged, b"a").await;
    assert_eq!(status, 403, "{body}");
    // The same user's own PutObject isn't a POST: the condition denies it.
    let sdk = common::client_as(&server, web.0, web.1);
    let put = sdk
        .put_object()
        .bucket("photos")
        .key("uploads/b.jpg")
        .body(ByteStream::from_static(b"b"))
        .send()
        .await;
    assert_eq!(common::code(put), "AccessDenied");
}

/// `s3:signatureAge` of a form is the time since its `x-amz-date`. (s3s refuses forms
/// signed more than 15 minutes ago, which AWS accepts until their policy expires.)
#[tokio::test]
async fn a_forms_age_is_when_it_was_signed() {
    let server = start().await;
    bucket(&server, "aged").await;
    client(&server, SECRET_KEY)
        .put_bucket_policy()
        .bucket("aged")
        .policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::aged/*","Condition":{"NumericGreaterThan":{"s3:signatureAge":"300000"}}}]}"#)
        .send()
        .await
        .unwrap();
    let form = |age: Duration| {
        signed_at(
            (ACCESS_KEY, SECRET_KEY),
            SystemTime::now() - age,
            FAR,
            &[
                json!({"bucket": "aged"}),
                json!(["starts-with", "$key", ""]),
            ],
            &[("key", "a")],
        )
    };
    let Answer { status, body, .. } = post(&server, "aged", &form(Duration::ZERO), b"a").await;
    assert_eq!(status, 204, "{body}");
    let Answer { status, body, .. } =
        post(&server, "aged", &form(Duration::from_mins(10)), b"a").await;
    assert_eq!(status, 403, "{body}");
}

#[tokio::test]
async fn anonymous_forms_need_a_bucket_policy_that_allows_them() {
    let server = start().await;
    bucket(&server, "drop").await;
    let fields = vec![("key".to_owned(), "inbox/a.txt".to_owned())];
    let Answer { status, .. } = post(&server, "drop", &fields, b"hello").await;
    assert_eq!(status, 403);
    let root = client(&server, SECRET_KEY);
    root.delete_public_access_block()
        .bucket("drop")
        .send()
        .await
        .unwrap();
    root.put_bucket_policy()
        .bucket("drop")
        .policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
                "Action":"s3:PutObject","Resource":"arn:aws:s3:::drop/inbox/*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let Answer { status, body, .. } = post(&server, "drop", &fields, b"hello").await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(read(&server, "drop", "inbox/a.txt").await, b"hello");
    let elsewhere = vec![("key".to_owned(), "a.txt".to_owned())];
    assert_eq!(post(&server, "drop", &elsewhere, b"x").await.status, 403);
}

/// A form part: the names its `Content-Disposition` headers give (the last counts), the
/// file's name, and its value.
#[derive(Debug, Clone)]
struct Part {
    names: Vec<String>,
    file_name: Option<String>,
    value: String,
}

/// A form body of `parts` as they come, the file last.
fn raw_body(parts: &[Part], file: &Part) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts.iter().chain([file]) {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        for name in &part.names {
            let file_name = part
                .file_name
                .as_ref()
                .map(|f| format!("; filename=\"{f}\""))
                .unwrap_or_default();
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"{file_name}\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(format!("\r\n{}\r\n", part.value).as_bytes());
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// Forms made of what decides which key a form names: `key` fields spelled any way,
/// repeated, renamed by a later header, and `${filename}` with any file name.
fn hostile_form() -> impl proptest::strategy::Strategy<Value = (Vec<Part>, Part)> {
    use proptest::prelude::*;
    let name = prop::sample::select(vec!["key", "KEY", "Key", "kEY", "keys", "ke", "acl"]);
    let pieces = vec![
        "inbox/",
        "inbox",
        "a",
        "/",
        "../",
        "..",
        "${filename}",
        "${FILENAME}",
        "%2e",
        "x/",
    ];
    // Mostly under `inbox/`, so that allowed and refused keys meet in one form.
    let text = (
        prop::bool::weighted(0.6),
        prop::collection::vec(prop::sample::select(pieces), 0..4),
    )
        .prop_map(|(inbox, pieces)| {
            let start = if inbox { "inbox/" } else { "" };
            format!("{start}{}", pieces.concat())
        });
    let part = (prop::collection::vec(name, 1..3), text.clone()).prop_map(|(names, value)| Part {
        names: names.into_iter().map(str::to_owned).collect(),
        file_name: None,
        value,
    });
    let file = (
        prop::sample::select(vec!["file", "FILE", "File"]),
        prop::option::of(text),
    )
        .prop_map(|(name, file_name)| Part {
            names: vec![name.to_owned()],
            file_name,
            value: "data".to_owned(),
        });
    (prop::collection::vec(part, 0..5), file)
}

/// Whatever a form says, an anonymous form allowed only `inbox/*` writes only there:
/// the key TeiFS authorizes is the key the upload goes to.
#[test]
fn a_form_writes_only_the_key_it_was_allowed() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(async {
        let server = start().await;
        bucket(&server, "drop").await;
        let root = client(&server, SECRET_KEY);
        root.delete_public_access_block()
            .bucket("drop")
            .send()
            .await
            .unwrap();
        root.put_bucket_policy()
            .bucket("drop")
            .policy(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
                    "Action":"s3:PutObject","Resource":"arn:aws:s3:::drop/inbox/*"}]}"#,
            )
            .send()
            .await
            .unwrap();
        server
    });
    let http = reqwest::Client::new();
    let cases = std::env::var("PROPTEST_CASES").map_or(256, |n| n.parse().unwrap());
    let mut runner =
        proptest::test_runner::TestRunner::new(proptest::test_runner::Config::with_cases(cases));
    let uploads = std::sync::atomic::AtomicUsize::new(0);
    runner
        .run(&hostile_form(), |(parts, file)| {
            runtime.block_on(async {
                let status = http
                    .post(format!("{}/drop", server.endpoint))
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={BOUNDARY}"),
                    )
                    .body(raw_body(&parts, &file))
                    .send()
                    .await
                    .unwrap()
                    .status();
                if status == 204 {
                    uploads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let listing = client(&server, SECRET_KEY)
                    .list_objects_v2()
                    .bucket("drop")
                    .send()
                    .await
                    .unwrap();
                for object in listing.contents() {
                    let key = object.key().unwrap();
                    proptest::prop_assert!(
                        key.starts_with("inbox/"),
                        "the bucket holds {key} (this form: {status})"
                    );
                }
                Ok(())
            })
        })
        .unwrap();
    assert!(uploads.into_inner() > 0, "no form was taken");
}

#[tokio::test]
async fn fields_are_read_however_they_arrive_and_only_so_much() {
    let server = start().await;
    bucket(&server, "photos").await;
    // A form sent a few bytes at a time.
    let form = root_form("photos", &[], &[("key", "slow.txt")]);
    let body = body(&form, "slow.txt", b"slowly");
    let address = server.endpoint.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let head = format!(
        "POST /photos HTTP/1.1\r\nHost: {address}\r\nContent-Type: multipart/form-data; boundary={BOUNDARY}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    for chunk in body.chunks(7) {
        stream.write_all(chunk).await.unwrap();
        stream.flush().await.unwrap();
    }
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 204"), "{answer}");
    assert_eq!(read(&server, "photos", "slow.txt").await, b"slowly");
    // Fields before the file larger than a form's may be.
    let padding = "p".repeat(70 * 1024);
    let form = root_form(
        "photos",
        &[json!(["starts-with", "$x-ignore-padding", ""])],
        &[("key", "big.txt"), ("x-ignore-padding", &padding)],
    );
    let Answer { status, body, .. } = post(&server, "photos", &form, b"x").await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("MaxPostPreDataLengthExceeded"), "{body}");
}

#[tokio::test]
async fn sessions_sign_forms_with_their_token_in_the_form() {
    let server = start().await;
    bucket(&server, "photos").await;
    let account = server.iam.account();
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{account}"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    server
        .iam
        .create_role(
            "uploader",
            &teifs_iam::NewRole {
                trust: &trust,
                ..teifs_iam::NewRole::default()
            },
        )
        .unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::Role("uploader"),
            "uploads",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::photos/*"}]}"#,
        )
        .unwrap();
    server.iam.create_user("web", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::User("web"),
            "assume",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}"#,
        )
        .unwrap();
    let key = server.iam.create_access_key("web").unwrap();
    let sts = aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_sts::config::Region::new("us-east-1"))
            .endpoint_url(&server.endpoint)
            .credentials_provider(aws_sdk_sts::config::Credentials::new(
                &key.info.id,
                key.secret.as_str(),
                None,
                None,
                "tests",
            ))
            .build(),
    );
    let out = sts
        .assume_role()
        .role_arn(format!("arn:aws:iam::{account}:role/uploader"))
        .role_session_name("browser")
        .send()
        .await
        .unwrap();
    let credentials = out.credentials().unwrap();
    let session = (credentials.access_key_id(), credentials.secret_access_key());
    let token = credentials.session_token();
    let form = |key: &str, fields: &[(&str, &str)], conditions: &[Value]| {
        let mut all = vec![json!({"bucket": "photos"}), json!({"key": key})];
        all.extend_from_slice(conditions);
        let mut named = vec![("key", key)];
        named.extend_from_slice(fields);
        signed(session, FAR, &all, &named)
    };

    let with_token = form(
        "a.jpg",
        &[("x-amz-security-token", token)],
        &[json!({"x-amz-security-token": token})],
    );
    let Answer { status, body, .. } = post(&server, "photos", &with_token, b"a").await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(read(&server, "photos", "a.jpg").await, b"a");
    let Answer { status, body, .. } = post(&server, "photos", &form("b.jpg", &[], &[]), b"b").await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("<Code>InvalidToken</Code>"), "{body}");
}
