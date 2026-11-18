//! The WebDAV gateway, end to end: WebDAV requests over HTTP and HTTPS, and what they did
//! checked over S3.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[macro_use]
mod common;

use std::net::SocketAddr;

use aws_sdk_s3::primitives::ByteStream;
use common::{ACCESS_KEY, SECRET_KEY, Server, certs::Authority};
use reqwest::{Method, StatusCode};
use teifs_server::{TlsSource, WebDavConfig};

/// The smallest part S3 takes: uploads bigger than it go in parts.
const PART: usize = 5 * 1024 * 1024;

/// A server with the WebDAV gateway on a free loopback port (plain HTTP).
async fn start_in(layout: teifs_store::Layout) -> Server {
    common::start_with(|config| {
        config.default_layout = layout;
        let mut webdav = WebDavConfig::new("127.0.0.1:0".parse().unwrap());
        webdav.part_size = PART;
        config.gateways.webdav = Some(webdav);
    })
    .await
}

fn url(at: SocketAddr, path: &str) -> String {
    format!("http://{at}{path}")
}

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).unwrap()
}

/// A WebDAV request signed in as the root key.
fn dav(http: &reqwest::Client, name: &str, address: String) -> reqwest::RequestBuilder {
    http.request(method(name), address)
        .basic_auth(ACCESS_KEY, Some(SECRET_KEY))
}

/// The names a `PROPFIND` with `Depth: 1` lists, the folder itself left out.
async fn listing(http: &reqwest::Client, at: SocketAddr, path: &str) -> Vec<String> {
    let answer = dav(http, "PROPFIND", url(at, path))
        .header("Depth", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), StatusCode::MULTI_STATUS);
    let body = answer.text().await.unwrap();
    let mut names: Vec<String> = body
        .split("<D:href>")
        .skip(1)
        .filter_map(|rest| rest.split("</D:href>").next())
        .map(|href| {
            percent_encoding::percent_decode_str(href.trim_end_matches('/'))
                .decode_utf8_lossy()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    names.remove(0);
    names.sort();
    names
}

in_both_layouts!(folders_and_files_are_buckets_and_objects);

#[expect(
    clippy::too_many_lines,
    reason = "one walk through every WebDAV method"
)]
async fn folders_and_files_are_buckets_and_objects(layout: teifs_store::Layout) {
    let server = start_in(layout).await;
    let at = server.webdav.unwrap();
    let s3 = common::client(&server, SECRET_KEY);
    let http = reqwest::Client::new();

    // Without credentials: asked for them.
    let answer = http
        .request(method("PROPFIND"), url(at, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
    assert!(
        answer.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Basic ")
    );

    // A folder at the top is a bucket; one in it is a prefix.
    let made = dav(&http, "MKCOL", url(at, "/notes")).send().await.unwrap();
    assert_eq!(made.status(), StatusCode::CREATED);
    s3.head_bucket().bucket("notes").send().await.unwrap();
    assert_eq!(
        dav(&http, "MKCOL", url(at, "/notes/2026"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(listing(&http, at, "/").await, ["notes"]);
    let everything = dav(&http, "PROPFIND", url(at, "/"))
        .header("Depth", "infinity")
        .send()
        .await
        .unwrap();
    assert_eq!(everything.status(), StatusCode::NOT_IMPLEMENTED);

    // A file put is an object.
    let put = dav(&http, "PUT", url(at, "/notes/2026/a%20b.txt"))
        .body("hello over webdav")
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);
    let got = s3
        .get_object()
        .bucket("notes")
        .key("2026/a b.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(got.content_type(), Some("text/plain"));
    assert_eq!(
        got.body.collect().await.unwrap().into_bytes().as_ref(),
        b"hello over webdav"
    );
    // Into a folder that isn't there: its prefix makes it, as over S3.
    let put = dav(&http, "PUT", url(at, "/notes/2026/new/x.txt"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);
    assert_eq!(
        dav(&http, "DELETE", url(at, "/notes/2026/new/x.txt"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    s3.put_object()
        .bucket("notes")
        .key("2026/deep/x.bin")
        .body(ByteStream::from_static(b"xyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        listing(&http, at, "/notes/2026/").await,
        ["a b.txt", "deep"]
    );

    // Reads, whole and in part.
    let read = dav(&http, "GET", url(at, "/notes/2026/a%20b.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(read.text().await.unwrap(), "hello over webdav");
    let part = dav(&http, "GET", url(at, "/notes/2026/a%20b.txt"))
        .header("Range", "bytes=6-9")
        .send()
        .await
        .unwrap();
    assert_eq!(part.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.text().await.unwrap(), "over");

    // Moves and copies of files.
    let moved = dav(&http, "MOVE", url(at, "/notes/2026/a%20b.txt"))
        .header("Destination", url(at, "/notes/2026/moved.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), StatusCode::CREATED);
    let copied = dav(&http, "COPY", url(at, "/notes/2026/moved.txt"))
        .header("Destination", url(at, "/notes/copy.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(copied.status(), StatusCode::CREATED);
    assert_eq!(
        listing(&http, at, "/notes/2026/").await,
        ["deep", "moved.txt"]
    );
    assert_eq!(listing(&http, at, "/notes/").await, ["2026", "copy.txt"]);
    // Not over another file when told not to.
    let refused = dav(&http, "MOVE", url(at, "/notes/copy.txt"))
        .header("Destination", url(at, "/notes/2026/moved.txt"))
        .header("Overwrite", "F")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::PRECONDITION_FAILED);

    // Locks are faked, for the clients that need them to write.
    let lock = dav(&http, "LOCK", url(at, "/notes/copy.txt"))
        .header("Content-Type", "application/xml")
        .body(
            r#"<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(lock.status(), StatusCode::OK);

    // Deletes: a file, then folders.
    assert_eq!(
        dav(&http, "DELETE", url(at, "/notes/copy.txt"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        s3.head_object()
            .bucket("notes")
            .key("copy.txt")
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        dav(&http, "GET", url(at, "/notes/copy.txt"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn big_files_go_up_in_parts() {
    let server = start_in(teifs_store::Layout::Object).await;
    let at = server.webdav.unwrap();
    let s3 = common::client(&server, SECRET_KEY);
    s3.create_bucket().bucket("big").send().await.unwrap();
    let data: Vec<u8> = (0..(2 * PART + 999))
        .map(|i| u8::try_from(i % 241).unwrap())
        .collect();
    let http = reqwest::Client::new();
    let put = dav(&http, "PUT", url(at, "/big/blob.bin"))
        .body(data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);
    let head = s3
        .head_object()
        .bucket("big")
        .key("blob.bin")
        .send()
        .await
        .unwrap();
    assert!(
        head.e_tag().unwrap().ends_with("-3\""),
        "{:?}",
        head.e_tag()
    );
    let read = dav(&http, "GET", url(at, "/big/blob.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(read.bytes().await.unwrap().as_ref(), data.as_slice());
}

#[tokio::test]
async fn keys_get_what_their_policies_allow_and_guessing_is_stopped() {
    let server = start_in(teifs_store::Layout::Object).await;
    let at = server.webdav.unwrap();
    let s3 = common::client(&server, SECRET_KEY);
    s3.create_bucket().bucket("shared").send().await.unwrap();
    s3.put_object()
        .bucket("shared")
        .key("readme.txt")
        .body(ByteStream::from_static(b"read me"))
        .send()
        .await
        .unwrap();
    server.iam.create_user("reader", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::User("reader"),
            "read",
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":["s3:ListBucket","s3:GetObject"],
                 "Resource":["arn:aws:s3:::shared","arn:aws:s3:::shared/*"]}]}"#,
        )
        .unwrap();
    let key = server.iam.create_access_key("reader").unwrap();
    let http = reqwest::Client::new();
    let as_reader = |name: &str, path: &str| {
        http.request(method(name), url(at, path))
            .basic_auth(&key.info.id, Some(key.secret.as_str()))
    };
    let read = as_reader("GET", "/shared/readme.txt").send().await.unwrap();
    assert_eq!(read.text().await.unwrap(), "read me");
    let put = as_reader("PUT", "/shared/new.txt")
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::FORBIDDEN);
    let delete = as_reader("DELETE", "/shared/readme.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::FORBIDDEN);
    s3.head_object()
        .bucket("shared")
        .key("readme.txt")
        .send()
        .await
        .unwrap();

    // A removed key stops working at once, though it signed in moments ago.
    server
        .iam
        .delete_access_key("reader", &key.info.id)
        .unwrap();
    let after = as_reader("GET", "/shared/readme.txt").send().await.unwrap();
    assert!(!after.status().is_success(), "{}", after.status());

    // Wrong secrets: refused, and after ten, even the right one is.
    for _ in 0..teifs_gateway::MAX_FAILURES {
        let wrong = http
            .request(method("PROPFIND"), url(at, "/"))
            .basic_auth(ACCESS_KEY, Some("wrong"))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }
    let blocked = dav(&http, "PROPFIND", url(at, "/")).send().await.unwrap();
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn plain_http_is_refused_off_loopback_and_https_is_served() {
    // Off loopback without certificates: refused at start.
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let mut config = common::config(dir.path(), keys.path());
    config.gateways.webdav = Some(WebDavConfig::new("0.0.0.0:0".parse().unwrap()));
    let err = teifs_server::Server::bind(config).await.err().unwrap();
    assert!(err.to_string().contains("in the clear"), "{err}");

    // With the server's certificates, it's HTTPS.
    let ca = Authority::new();
    let certs = tempfile::tempdir().unwrap();
    ca.issue_into(certs.path(), &["localhost", "127.0.0.1"]);
    let server = common::start_with(|config| {
        config.tls = Some(TlsSource::Dir(certs.path().to_owned()));
        config.gateways.webdav = Some(WebDavConfig::new("127.0.0.1:0".parse().unwrap()));
    })
    .await;
    let at = server.webdav.unwrap();
    let http = ca.reqwest();
    let answer = dav(&http, "PROPFIND", format!("https://{at}/"))
        .header("Depth", "0")
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), StatusCode::MULTI_STATUS);
    assert_eq!(answer.headers()["x-content-type-options"], "nosniff");

    // Off by default.
    let plain = common::start().await;
    assert!(plain.webdav.is_none());
}
