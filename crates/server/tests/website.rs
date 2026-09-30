//! Static website hosting over the S3 API: `PutBucketWebsite` with AWS's checks and
//! messages, `GetBucketWebsite` answering it as it was given, `DeleteBucketWebsite`.

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

use common::{SECRET_KEY, client, code, start, user};

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
