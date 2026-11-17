//! The web console end to end: its page and headers, signing in and out, and calls
//! passed on to S3, IAM and STS as the signed-in key's, with no more authority.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use reqwest::{Method, StatusCode, header};
use teifs_console::{API_CSP, APP_CSP, CONSOLE_HEADER, PLAIN_COOKIE};

async fn start() -> (common::Server, String) {
    let server = common::start_with(|config| {
        config.console = Some("127.0.0.1:0".parse().unwrap());
    })
    .await;
    let console = server.console.clone().expect("the console is served");
    (server, console)
}

/// A browser on the console's page: same-origin calls with the console's header, and
/// the session cookie once it has one.
struct Page {
    http: reqwest::Client,
    origin: String,
    cookie: Option<String>,
}

impl Page {
    fn new(origin: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            origin: origin.to_owned(),
            cookie: None,
        }
    }

    fn call(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.origin))
            .header(CONSOLE_HEADER, "1")
            .header(header::ORIGIN, &self.origin)
            .header("sec-fetch-site", "same-origin");
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, cookie);
        }
        request
    }

    async fn sign_in(&mut self, access_key: &str, secret: &str) -> reqwest::Response {
        let response = self
            .call(Method::POST, "/api/session")
            .json(&serde_json::json!({ "accessKey": access_key, "secretKey": secret }))
            .send()
            .await
            .unwrap();
        if let Some(set) = response.headers().get(header::SET_COOKIE) {
            let pair = set.to_str().unwrap().split(';').next().unwrap().to_owned();
            self.cookie = Some(pair);
        }
        response
    }
}

#[tokio::test]
async fn the_page_is_served_with_its_policies() {
    let (_server, console) = start().await;
    let page = reqwest::get(format!("{console}/")).await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let headers = page.headers().clone();
    assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], APP_CSP);
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert!(page.text().await.unwrap().contains("app.js"));
    let script = reqwest::get(format!("{console}/app.js")).await.unwrap();
    assert_eq!(
        script.headers()[header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
    let missing = reqwest::get(format!("{console}/../crates/console/Cargo.toml"))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn calls_from_elsewhere_than_the_page_are_refused() {
    let (_server, console) = start().await;
    let http = reqwest::Client::new();
    // A form or link on another site: no console header.
    let plain = http
        .post(format!("{console}/api/session"))
        .json(&serde_json::json!({ "accessKey": common::ACCESS_KEY, "secretKey": common::SECRET_KEY }))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), StatusCode::FORBIDDEN);
    assert_eq!(plain.headers()[header::CONTENT_SECURITY_POLICY], API_CSP);
    // A script on another site, which a browser marks as one.
    for (name, value) in [
        ("sec-fetch-site", "cross-site"),
        ("origin", "http://evil.example"),
    ] {
        let response = http
            .get(format!("{console}/api/session"))
            .header(CONSOLE_HEADER, "1")
            .header(name, value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}: {value}");
    }
    // A download link followed from another site.
    let link = http
        .get(format!("{console}/api/download/b/k"))
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(link.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn signing_in_needs_a_key_that_signs() {
    let (_server, console) = start().await;
    let mut page = Page::new(&console);
    let before = page.call(Method::GET, "/api/session").send().await.unwrap();
    assert_eq!(before.status(), StatusCode::UNAUTHORIZED);
    let wrong = page.sign_in(common::ACCESS_KEY, "not-the-secret").await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(page.cookie.is_none(), "a refused sign-in sets no cookie");
    let body: serde_json::Value = wrong.json().await.unwrap();
    assert_eq!(body["code"], "SignInRefused");
    let unknown = page.sign_in("nobody", "nothing").await;
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);

    let right = page.sign_in(common::ACCESS_KEY, common::SECRET_KEY).await;
    assert_eq!(right.status(), StatusCode::OK);
    let cookie = right.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with(&format!("{PLAIN_COOKIE}=")), "{cookie}");
    for attribute in ["HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(attribute), "{cookie}");
    }
    assert!(!cookie.contains(common::SECRET_KEY));
    let who: serde_json::Value = right.json().await.unwrap();
    assert!(who["arn"].as_str().unwrap().ends_with(":root"), "{who}");
    assert_eq!(who["accessKey"], common::ACCESS_KEY);
    assert!(who.get("secretKey").is_none());

    let now = page.call(Method::GET, "/api/session").send().await.unwrap();
    assert_eq!(now.status(), StatusCode::OK);

    // A cookie that names no session is no session.
    let forged = Page {
        cookie: Some(format!(
            "{PLAIN_COOKIE}=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )),
        ..Page::new(&console)
    };
    let refused = forged.call(Method::GET, "/api/s3/").send().await.unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

    // Signing out ends it, and clears the cookie.
    let out = page
        .call(Method::DELETE, "/api/session")
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::NO_CONTENT);
    assert!(
        out.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let after = page.call(Method::GET, "/api/s3/").send().await.unwrap();
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn failed_sign_ins_are_limited() {
    let (_server, console) = start().await;
    let mut page = Page::new(&console);
    for _ in 0..10 {
        let wrong = page.sign_in(common::ACCESS_KEY, "guess").await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }
    // Even the right key waits now.
    let limited = page.sign_in(common::ACCESS_KEY, common::SECRET_KEY).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn s3_calls_go_through_as_the_signed_in_key() {
    let (server, console) = start().await;
    let mut page = Page::new(&console);
    assert_eq!(
        page.sign_in(common::ACCESS_KEY, common::SECRET_KEY)
            .await
            .status(),
        StatusCode::OK
    );
    let created = page
        .call(Method::PUT, "/api/s3/photos")
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let listed = page.call(Method::GET, "/api/s3/").send().await.unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(listed.headers()[header::CONTENT_SECURITY_POLICY], API_CSP);
    assert_eq!(listed.headers()[header::CACHE_CONTROL], "no-store");
    assert!(listed.text().await.unwrap().contains("<Name>photos</Name>"));

    // A small object (read, hashed and signed) and a big one (streamed), with keys that
    // need encoding.
    let small = b"hello".to_vec();
    let big: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    for (key, path, body) in [
        (
            "a b/café.txt",
            "/api/s3/photos/a%20b/caf%C3%A9.txt",
            small.clone(),
        ),
        (
            "big (1).bin",
            "/api/s3/photos/big%20%281%29.bin",
            big.clone(),
        ),
    ] {
        let put = page
            .call(Method::PUT, path)
            .header("x-amz-meta-colour", "blue")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            put.status(),
            StatusCode::OK,
            "{key}: {}",
            put.text().await.unwrap()
        );
        let s3 = common::client(&server, common::SECRET_KEY);
        let got = s3
            .get_object()
            .bucket("photos")
            .key(key)
            .send()
            .await
            .unwrap();
        assert_eq!(got.metadata().unwrap()["colour"], "blue");
        assert_eq!(got.body.collect().await.unwrap().into_bytes(), body);
    }

    // A download is an attachment that can't run as a page on the console's origin.
    let link = page
        .call(Method::GET, "/api/download/photos/a%20b/caf%C3%A9.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(link.status(), StatusCode::OK);
    let disposition = link.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap();
    assert!(disposition.starts_with("attachment;"), "{disposition}");
    assert!(
        disposition.contains("filename*=UTF-8''caf%C3%A9.txt"),
        "{disposition}"
    );
    assert_eq!(link.headers()[header::CONTENT_SECURITY_POLICY], API_CSP);
    assert_eq!(link.bytes().await.unwrap(), small);

    // S3's own errors come back as S3 answers them.
    let missing = page
        .call(Method::GET, "/api/s3/photos/missing")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert!(
        missing
            .text()
            .await
            .unwrap()
            .contains("<Code>NoSuchKey</Code>")
    );
}

#[tokio::test]
async fn bodies_get_what_s3_asks_for_and_no_signature_from_the_page() {
    let (_server, console) = start().await;
    let mut page = Page::new(&console);
    page.sign_in(common::ACCESS_KEY, common::SECRET_KEY).await;
    page.call(Method::PUT, "/api/s3/photos")
        .send()
        .await
        .unwrap();
    page.call(Method::PUT, "/api/s3/photos/big%20%281%29.bin")
        .body("x")
        .send()
        .await
        .unwrap();
    // Bodies with a Content-MD5 S3 asks for (DeleteObjects) get one.
    let delete = page
        .call(Method::POST, "/api/s3/photos?delete")
        .header(header::CONTENT_TYPE, "application/xml")
        .body("<Delete><Object><Key>big (1).bin</Key></Object></Delete>")
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);
    assert!(delete.text().await.unwrap().contains("<Deleted>"));

    // The page can't sign requests itself.
    let presigned = page
        .call(Method::GET, "/api/s3/photos/x?X-Amz-Signature=abc")
        .send()
        .await
        .unwrap();
    assert_eq!(presigned.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_key_can_do_no_more_in_the_console_than_its_policies_allow() {
    let (server, console) = start().await;
    server.iam.create_user("ana", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::User("ana"),
            "read",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#,
        )
        .unwrap();
    let key = server.iam.create_access_key("ana").unwrap();
    let mut page = Page::new(&console);
    let signed_in = page.sign_in(&key.info.id, &key.secret).await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let who: serde_json::Value = signed_in.json().await.unwrap();
    assert!(who["arn"].as_str().unwrap().ends_with(":user/ana"), "{who}");

    let listed = page.call(Method::GET, "/api/s3/").send().await.unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let create = page.call(Method::PUT, "/api/s3/hers").send().await.unwrap();
    assert_eq!(create.status(), StatusCode::FORBIDDEN);
    assert!(create.text().await.unwrap().contains("AccessDenied"));
    let users = page
        .call(Method::POST, "/api/iam")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("Action=ListUsers&Version=2010-05-08")
        .send()
        .await
        .unwrap();
    assert_eq!(users.status(), StatusCode::FORBIDDEN);

    // Deleting the key ends what the session can do at once.
    server.iam.delete_access_key("ana", &key.info.id).unwrap();
    let after = page.call(Method::GET, "/api/s3/").send().await.unwrap();
    assert_eq!(after.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn iam_and_sts_calls_go_through() {
    let (_server, console) = start().await;
    let mut page = Page::new(&console);
    page.sign_in(common::ACCESS_KEY, common::SECRET_KEY).await;
    let form = |body: &'static str| {
        page.call(Method::POST, "/api/iam")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
    };
    let created = form("Action=CreateUser&UserName=bo&Version=2010-05-08")
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let listed = form("Action=ListUsers&Version=2010-05-08")
        .send()
        .await
        .unwrap();
    assert!(
        listed
            .text()
            .await
            .unwrap()
            .contains("<UserName>bo</UserName>")
    );
    let me = page
        .call(Method::POST, "/api/sts")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("Action=GetCallerIdentity&Version=2011-06-15")
        .send()
        .await
        .unwrap();
    assert!(me.text().await.unwrap().contains(":root</Arn>"));
    let get = page.call(Method::GET, "/api/iam").send().await.unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn plain_http_off_loopback_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let mut config = common::config(dir.path(), keys.path());
    config.console = Some("0.0.0.0:0".parse().unwrap());
    let refused = Box::pin(teifs_server::Server::bind(config))
        .await
        .unwrap_err();
    assert!(
        matches!(refused, teifs_server::ServerError::Console(_)),
        "{refused}"
    );
}

#[tokio::test]
async fn the_console_is_off_unless_asked_for() {
    let server = common::start().await;
    assert!(server.console.is_none());
}

#[tokio::test]
async fn multipart_uploads_go_through_as_the_page_sends_them() {
    let (server, console) = start().await;
    let mut page = Page::new(&console);
    page.sign_in(common::ACCESS_KEY, common::SECRET_KEY).await;
    page.call(Method::PUT, "/api/s3/big").send().await.unwrap();
    let key_path = "/api/s3/big/movie%20%C3%A9.bin";
    let created = page
        .call(Method::POST, &format!("{key_path}?uploads"))
        .header(header::CONTENT_TYPE, "video/mp4")
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let xml = created.text().await.unwrap();
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|rest| rest.split("</UploadId>").next())
        .unwrap()
        .to_owned();
    // A part over the console's read limit is streamed; the last one is read.
    let first: Vec<u8> = vec![7; 5 * 1024 * 1024];
    let last: Vec<u8> = vec![9; 1000];
    let mut etags = Vec::new();
    for (number, part) in [(1, &first), (2, &last)] {
        let sent = page
            .call(
                Method::PUT,
                &format!("{key_path}?partNumber={number}&uploadId={upload_id}"),
            )
            .body(part.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(sent.status(), StatusCode::OK);
        etags.push(sent.headers()[header::ETAG].to_str().unwrap().to_owned());
    }
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let done = page
        .call(Method::POST, &format!("{key_path}?uploadId={upload_id}"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(complete)
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), StatusCode::OK);
    let s3 = common::client(&server, common::SECRET_KEY);
    let got = s3
        .head_object()
        .bucket("big")
        .key("movie é.bin")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.content_length(),
        Some((first.len() + last.len()) as i64)
    );
    assert_eq!(got.content_type(), Some("video/mp4"));
    assert!(got.e_tag().unwrap().ends_with("-2\""));
}

#[tokio::test]
async fn versions_are_listed_and_deleted_through_the_console() {
    let (server, console) = start().await;
    let mut page = Page::new(&console);
    page.sign_in(common::ACCESS_KEY, common::SECRET_KEY).await;
    page.call(Method::PUT, "/api/s3/kept").send().await.unwrap();
    let versioning = page
        .call(Method::PUT, "/api/s3/kept?versioning")
        .header(header::CONTENT_TYPE, "application/xml")
        .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
        .send()
        .await
        .unwrap();
    assert_eq!(versioning.status(), StatusCode::OK);
    for body in ["one", "two"] {
        page.call(Method::PUT, "/api/s3/kept/doc.txt")
            .body(body)
            .send()
            .await
            .unwrap();
    }
    let listed = page
        .call(Method::GET, "/api/s3/kept?versions&prefix=&delimiter=%2F")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(listed.matches("<Version>").count(), 2, "{listed}");
    let older = listed
        .split("<VersionId>")
        .nth(2)
        .and_then(|rest| rest.split("</VersionId>").next())
        .unwrap()
        .to_owned();
    let old = page
        .call(
            Method::GET,
            &format!("/api/download/kept/doc.txt?versionId={older}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(old.text().await.unwrap(), "one");
    let deleted = page
        .call(
            Method::DELETE,
            &format!("/api/s3/kept/doc.txt?versionId={older}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let s3 = common::client(&server, common::SECRET_KEY);
    let versions = s3
        .list_object_versions()
        .bucket("kept")
        .send()
        .await
        .unwrap();
    assert_eq!(versions.versions().len(), 1);
}
