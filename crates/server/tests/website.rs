//! Static website hosting: `PutBucketWebsite` with AWS's checks and messages,
//! `GetBucketWebsite` answering it as it was given, `DeleteBucketWebsite`, and the
//! website endpoint serving buckets' objects as S3's does.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,
    types::{
        Condition, ErrorDocument, IndexDocument, Protocol, Redirect, RedirectAllRequestsTo,
        RoutingRule, WebsiteConfiguration,
    },
};

mod common;

use aws_sdk_s3::primitives::ByteStream;
use common::{SECRET_KEY, Server, client, code, start, start_with, user};
use reqwest::{Method, header};

/// The domain websites are served on in these tests.
const DOMAIN: &str = "web.test";

fn index(suffix: &str) -> IndexDocument {
    IndexDocument::builder().suffix(suffix).build().unwrap()
}

fn to_host(host: &str) -> Redirect {
    Redirect::builder().host_name(host).build()
}

async fn put(s3: &Client, bucket: &str, config: WebsiteConfiguration) -> String {
    code(
        s3.put_bucket_website()
            .bucket(bucket)
            .website_configuration(config)
            .send()
            .await,
    )
}

/// The code and message S3 refuses `config` with.
async fn refused(s3: &Client, config: WebsiteConfiguration) -> (String, String) {
    let err = s3
        .put_bucket_website()
        .bucket("site")
        .website_configuration(config)
        .send()
        .await
        .unwrap_err();
    (
        err.code().unwrap_or_default().to_owned(),
        err.message().unwrap_or_default().to_owned(),
    )
}

#[tokio::test]
async fn a_website_is_answered_as_it_was_given() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("site").send().await.unwrap();
    let missing = root.get_bucket_website().bucket("site").send().await;
    assert_eq!(code(missing), "NoSuchWebsiteConfiguration");
    let rules = vec![
        RoutingRule::builder()
            .condition(Condition::builder().key_prefix_equals("docs/").build())
            .redirect(
                Redirect::builder()
                    .replace_key_prefix_with("documents/")
                    .build(),
            )
            .build(),
        RoutingRule::builder()
            .condition(
                Condition::builder()
                    .http_error_code_returned_equals("404")
                    .build(),
            )
            .redirect(
                Redirect::builder()
                    .host_name("example.com")
                    .protocol(Protocol::Https)
                    .http_redirect_code("302")
                    .replace_key_with("missing.html")
                    .build(),
            )
            .build(),
    ];
    let site = WebsiteConfiguration::builder()
        .index_document(index("index.html"))
        .error_document(ErrorDocument::builder().key("404.html").build().unwrap())
        .set_routing_rules(Some(rules.clone()))
        .build();
    assert_eq!(put(&root, "site", site).await, "ok");
    let got = root
        .get_bucket_website()
        .bucket("site")
        .send()
        .await
        .unwrap();
    assert_eq!(got.index_document(), Some(&index("index.html")));
    assert_eq!(
        got.error_document().map(ErrorDocument::key),
        Some("404.html")
    );
    assert_eq!(got.routing_rules(), rules.as_slice());
    assert_eq!(got.redirect_all_requests_to(), None);
    // Replaced whole by another configuration.
    let all = RedirectAllRequestsTo::builder()
        .host_name("example.com")
        .build()
        .unwrap();
    let config = WebsiteConfiguration::builder()
        .redirect_all_requests_to(all.clone())
        .build();
    assert_eq!(put(&root, "site", config).await, "ok");
    let got = root
        .get_bucket_website()
        .bucket("site")
        .send()
        .await
        .unwrap();
    assert_eq!(got.redirect_all_requests_to(), Some(&all));
    assert_eq!(got.index_document(), None);
    // Deleted, even twice.
    for _ in 0..2 {
        root.delete_bucket_website()
            .bucket("site")
            .send()
            .await
            .unwrap();
    }
    let missing = root.get_bucket_website().bucket("site").send().await;
    assert_eq!(code(missing), "NoSuchWebsiteConfiguration");
    let nothing = root.get_bucket_website().bucket("nothing").send().await;
    assert_eq!(code(nothing), "NoSuchBucket");
}

#[tokio::test]
async fn websites_are_refused_as_s3_refuses_them() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("site").send().await.unwrap();
    let rule = |redirect: Redirect| RoutingRule::builder().redirect(redirect).build();
    let with_rules = |rules: Vec<RoutingRule>| {
        WebsiteConfiguration::builder()
            .index_document(index("index.html"))
            .set_routing_rules(Some(rules))
            .build()
    };
    let invalid_request = |message: &str| ("InvalidRequest".to_owned(), message.to_owned());
    assert_eq!(
        refused(&root, WebsiteConfiguration::builder().build()).await,
        (
            "InvalidArgument".to_owned(),
            "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty"
                .to_owned()
        )
    );
    let nested = WebsiteConfiguration::builder()
        .index_document(index("a/index.html"))
        .build();
    assert_eq!(
        refused(&root, nested).await,
        (
            "InvalidArgument".to_owned(),
            "The IndexDocument Suffix is not well formed".to_owned()
        )
    );
    let both = WebsiteConfiguration::builder()
        .index_document(index("index.html"))
        .redirect_all_requests_to(
            RedirectAllRequestsTo::builder()
                .host_name("example.com")
                .build()
                .unwrap(),
        )
        .build();
    assert_eq!(refused(&root, both).await.0, "MalformedXML");
    let many = (0..51).map(|_| rule(to_host("example.com"))).collect();
    assert_eq!(
        refused(&root, with_rules(many)).await,
        invalid_request(
            "51 routing rules provided, the number of routing rules in a website configuration \
             is limited to 50."
        )
    );
    let code_300 = Redirect::builder().http_redirect_code("300").build();
    assert_eq!(
        refused(&root, with_rules(vec![rule(code_300)])).await,
        invalid_request(
            "The provided HTTP redirect code (300) is not valid. Valid codes are 3XX except 300."
        )
    );
    let two_keys = Redirect::builder()
        .replace_key_with("a")
        .replace_key_prefix_with("b/")
        .build();
    assert_eq!(
        refused(&root, with_rules(vec![rule(two_keys)])).await,
        invalid_request("You can only define ReplaceKeyPrefix or ReplaceKey but not both.")
    );
    let on_302 = RoutingRule::builder()
        .condition(
            Condition::builder()
                .http_error_code_returned_equals("302")
                .build(),
        )
        .redirect(to_host("example.com"))
        .build();
    assert_eq!(
        refused(&root, with_rules(vec![on_302])).await,
        invalid_request(
            "The provided HTTP error code (302) is not valid. Valid codes are 4XX or 5XX."
        )
    );
    // Nothing was stored.
    let missing = root.get_bucket_website().bucket("site").send().await;
    assert_eq!(code(missing), "NoSuchWebsiteConfiguration");
}

#[tokio::test]
async fn websites_take_their_own_permissions() {
    let server = start().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("site").send().await.unwrap();
    let site = || {
        WebsiteConfiguration::builder()
            .index_document(index("index.html"))
            .build()
    };
    let reader = user(
        &server,
        "reader",
        Some(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetBucketWebsite","Resource":"arn:aws:s3:::site"}}"#,
        ),
    );
    assert_eq!(put(&reader, "site", site()).await, "AccessDenied");
    let delete = reader.delete_bucket_website().bucket("site").send().await;
    assert_eq!(code(delete), "AccessDenied");
    assert_eq!(put(&root, "site", site()).await, "ok");
    let got = reader.get_bucket_website().bucket("site").send().await;
    assert_eq!(code(got), "ok");
    let other = root.get_bucket_website().bucket("site").send().await;
    assert_eq!(code(other), "ok");
}

async fn website_server() -> Server {
    start_with(|config| config.website_domains = vec![DOMAIN.to_owned()]).await
}

/// A request to `host`'s website, as a browser sends it.
async fn visit(
    server: &Server,
    method: Method,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> reqwest::Response {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut request = client
        .request(method, format!("{}{path}", server.endpoint))
        .header(header::HOST, host);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().await.unwrap()
}

/// The status, a header and the body of a `GET` of `path` on bucket `site`'s website.
async fn get(server: &Server, path: &str, name: &str) -> (u16, String, String) {
    let answer = visit(server, Method::GET, "site.web.test", path, &[]).await;
    let status = answer.status().as_u16();
    let value = answer
        .headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (status, value, answer.text().await.unwrap())
}

async fn put_object(s3: &Client, key: &str, body: &str) {
    s3.put_object()
        .bucket("site")
        .key(key)
        .content_type("text/html")
        .body(ByteStream::from(body.as_bytes().to_vec()))
        .send()
        .await
        .unwrap();
}

/// Bucket `site`, whose objects anybody may read but those under `private/`, with an
/// index and an error document. Anybody may list it, as AWS advises, so a missing
/// object is `404 Not Found` rather than `403 Forbidden`.
async fn public_site(server: &Server) -> Client {
    let root = client(server, SECRET_KEY);
    root.create_bucket().bucket("site").send().await.unwrap();
    root.delete_public_access_block()
        .bucket("site")
        .send()
        .await
        .unwrap();
    root.put_bucket_policy()
        .bucket("site")
        .policy(
            r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::site"},
            {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::site/*"},
            {"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::site/private/*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    for (key, body) in [
        ("index.html", "home"),
        ("about/index.html", "about"),
        ("404.html", "not here"),
        ("private/index.html", "secret"),
    ] {
        put_object(&root, key, body).await;
    }
    let site = WebsiteConfiguration::builder()
        .index_document(index("index.html"))
        .error_document(ErrorDocument::builder().key("404.html").build().unwrap())
        .build();
    assert_eq!(put(&root, "site", site).await, "ok");
    root
}

#[tokio::test]
async fn websites_serve_what_anybody_may_read() {
    let server = website_server().await;
    let root = public_site(&server).await;
    assert_eq!(
        get(&server, "/", "content-type").await,
        (200, "text/html".to_owned(), "home".to_owned())
    );
    assert_eq!(get(&server, "/about/", "").await.2, "about");
    assert_eq!(get(&server, "/index.html", "").await.2, "home");
    // A folder without its slash is sent to it.
    assert_eq!(
        get(&server, "/about", "location").await,
        (302, "/about/".to_owned(), String::new())
    );
    // Errors get the error document, with their status.
    assert_eq!(
        get(&server, "/missing", "x-amz-error-code").await,
        (404, "NoSuchKey".to_owned(), "not here".to_owned())
    );
    assert_eq!(
        get(&server, "/private/", "x-amz-error-code").await,
        (403, "AccessDenied".to_owned(), "not here".to_owned())
    );
    // Not a folder whose index anybody may read: no redirect.
    assert_eq!(get(&server, "/private", "").await.0, 404);
    // An S3 read: ranges and conditions apply.
    let range = visit(
        &server,
        Method::GET,
        "site.web.test",
        "/",
        &[("range", "bytes=1-2")],
    )
    .await;
    assert_eq!(range.status().as_u16(), 206);
    assert_eq!(range.text().await.unwrap(), "om");
    let etag = visit(&server, Method::HEAD, "site.web.test:80", "/", &[]).await;
    assert_eq!(etag.status().as_u16(), 200);
    let etag = etag.headers()["etag"].to_str().unwrap().to_owned();
    let unchanged = visit(
        &server,
        Method::GET,
        "SITE.web.test",
        "/",
        &[("if-none-match", &etag)],
    )
    .await;
    assert_eq!(unchanged.status().as_u16(), 304);
    assert_eq!(
        unchanged.headers()["etag"],
        etag.as_str(),
        "S3's answer, not an error"
    );
    assert!(!unchanged.headers().contains_key("x-amz-error-code"));
    // The server's own paths are the site's keys on its host.
    assert_eq!(get(&server, "/.teifs/health", "").await.0, 404);
    // Only reads.
    let post = visit(&server, Method::POST, "site.web.test", "/", &[]).await;
    assert_eq!(post.status().as_u16(), 405);
    assert_eq!(post.headers()["x-amz-error-code"], "MethodNotAllowed");
    // Without the error document, S3's page, saying why it couldn't be read too.
    root.delete_object()
        .bucket("site")
        .key("404.html")
        .send()
        .await
        .unwrap();
    let (status, kind, page) = get(&server, "/missing", "content-type").await;
    assert_eq!((status, kind.as_str()), (404, "text/html; charset=utf-8"));
    assert!(
        page.starts_with("<html>\n<head><title>404 Not Found</title></head>"),
        "{page}"
    );
    assert!(page.contains("<li>Code: NoSuchKey</li>\n<li>Message: The specified key does not exist.</li>\n<li>Key: missing</li>"), "{page}");
    assert!(page.contains("<h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>\n<ul>\n<li>Code: NoSuchKey</li>"), "{page}");
    let head = visit(&server, Method::HEAD, "site.web.test", "/missing", &[]).await;
    assert_eq!(head.status().as_u16(), 404);
    assert_eq!(head.headers()["x-amz-error-code"], "NoSuchKey");
    // The S3 API on the same listener is unchanged.
    let listed = root.list_objects_v2().bucket("site").send().await.unwrap();
    assert_eq!(listed.key_count(), Some(3));
}

#[tokio::test]
async fn buckets_that_arent_websites_say_so() {
    let server = website_server().await;
    let root = client(&server, SECRET_KEY);
    root.create_bucket().bucket("site").send().await.unwrap();
    let (status, code, page) = get(&server, "/", "x-amz-error-code").await;
    assert_eq!((status, code.as_str()), (404, "NoSuchWebsiteConfiguration"));
    assert!(page.contains("<li>BucketName: site</li>"), "{page}");
    for host in ["nothing.web.test", "web.test"] {
        let answer = visit(&server, Method::GET, host, "/", &[]).await;
        assert_eq!(answer.status().as_u16(), 404, "{host}");
        assert_eq!(
            answer.headers()["x-amz-error-code"],
            "NoSuchBucket",
            "{host}"
        );
    }
    // A website whose objects nobody else may read: private stays private.
    put_object(&root, "index.html", "home").await;
    let site = WebsiteConfiguration::builder()
        .index_document(index("index.html"))
        .build();
    assert_eq!(put(&root, "site", site).await, "ok");
    let (status, code, _) = get(&server, "/", "x-amz-error-code").await;
    assert_eq!((status, code.as_str()), (403, "AccessDenied"));
}

#[tokio::test]
async fn websites_redirect_as_they_are_told() {
    let server = website_server().await;
    let root = public_site(&server).await;
    // An object that's elsewhere, which writes check.
    root.put_object()
        .bucket("site")
        .key("old.html")
        .website_redirect_location("/about/")
        .send()
        .await
        .unwrap();
    assert_eq!(
        get(&server, "/old.html", "location").await,
        (301, "/about/".to_owned(), String::new())
    );
    let refused = root
        .put_object()
        .bucket("site")
        .key("bad.html")
        .website_redirect_location("about/")
        .send()
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Some("InvalidRedirectLocation"));
    assert_eq!(refused.raw_response().unwrap().status().as_u16(), 400);
    // Routing rules: by prefix before reading, and by error after.
    let rules = vec![
        RoutingRule::builder()
            .condition(Condition::builder().key_prefix_equals("docs/").build())
            .redirect(
                Redirect::builder()
                    .replace_key_prefix_with("documents/")
                    .build(),
            )
            .build(),
        RoutingRule::builder()
            .condition(
                Condition::builder()
                    .http_error_code_returned_equals("404")
                    .build(),
            )
            .redirect(
                Redirect::builder()
                    .host_name("example.com")
                    .protocol(Protocol::Https)
                    .http_redirect_code("307")
                    .replace_key_prefix_with("lost/")
                    .build(),
            )
            .build(),
    ];
    let site = WebsiteConfiguration::builder()
        .index_document(index("index.html"))
        .set_routing_rules(Some(rules))
        .build();
    assert_eq!(put(&root, "site", site).await, "ok");
    assert_eq!(
        get(&server, "/docs/a%20b.html", "location").await.1,
        "http://site.web.test/documents/a%20b.html"
    );
    assert_eq!(
        get(&server, "/gone", "location").await,
        (
            307,
            "https://example.com/lost/gone".to_owned(),
            String::new()
        )
    );
    assert_eq!(get(&server, "/", "").await.2, "home", "found: no redirect");
    // Every request elsewhere.
    let all = RedirectAllRequestsTo::builder()
        .host_name("example.org")
        .protocol(Protocol::Https)
        .build()
        .unwrap();
    let config = WebsiteConfiguration::builder()
        .redirect_all_requests_to(all)
        .build();
    assert_eq!(put(&root, "site", config).await, "ok");
    assert_eq!(
        get(&server, "/a/b?c=d", "location").await,
        (301, "https://example.org/a/b?c=d".to_owned(), String::new())
    );
}

#[tokio::test]
async fn website_answers_follow_the_buckets_cors() {
    let server = website_server().await;
    let root = public_site(&server).await;
    let rule = aws_sdk_s3::types::CorsRule::builder()
        .allowed_origins("https://app.example")
        .allowed_methods("GET")
        .build()
        .unwrap();
    root.put_bucket_cors()
        .bucket("site")
        .cors_configuration(
            aws_sdk_s3::types::CorsConfiguration::builder()
                .cors_rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let origin = [("origin", "https://app.example")];
    let answer = visit(&server, Method::GET, "site.web.test", "/", &origin).await;
    assert_eq!(
        answer.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    let preflight = visit(
        &server,
        Method::OPTIONS,
        "site.web.test",
        "/",
        &[
            ("origin", "https://app.example"),
            ("access-control-request-method", "GET"),
        ],
    )
    .await;
    assert_eq!(preflight.status().as_u16(), 200);
}

#[tokio::test]
async fn a_domain_is_for_websites_or_for_s3() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let mut config = common::config(dir.path(), keys.path());
    config.domains = vec!["Example.com".to_owned()];
    config.website_domains = vec!["example.com.".to_owned()];
    let refused = teifs_server::Server::bind(config).await.err().unwrap();
    assert!(
        refused.to_string().contains("--website-domain"),
        "{refused}"
    );
}
