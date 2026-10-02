//! Prometheus metrics: only for bearer tokens of keys that may `teifs:GetMetrics` (or
//! anyone, when the server says so), counting every request by operation, status and
//! error code; and the request id every answer carries.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use std::time::Duration;

use aws_sdk_s3::{operation::RequestId, primitives::ByteStream};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, start_with};
use teifs_types::admin::METRICS_PATH;

/// A scrape's status, `WWW-Authenticate` header and body.
async fn scrape(server: &Server, token: Option<&str>) -> (u16, Option<String>, String) {
    let mut request = reqwest::Client::new().get(format!("{}{METRICS_PATH}", server.endpoint));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_owned());
    if status == 200 {
        assert_eq!(
            response.headers()["content-type"],
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );
    }
    (status, challenge, response.text().await.unwrap())
}

/// The value of the sample `series` (name and labels) in `text`.
fn value(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .map(|v| v.parse().unwrap())
}

/// The metrics once every series in `wanted` has at least its value: a request is
/// recorded when its answer's body is dropped, just after the client has it all.
async fn metrics_with(server: &Server, wanted: &[(&str, f64)]) -> String {
    let token = teifs_iam::metrics_token(ACCESS_KEY, SECRET_KEY, None);
    for _ in 0..100 {
        let (status, _, text) = scrape(server, Some(&token)).await;
        assert_eq!(status, 200, "{text}");
        if wanted
            .iter()
            .all(|(series, least)| value(&text, series).is_some_and(|v| v >= *least))
        {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never saw {wanted:?}");
}

#[tokio::test]
async fn scrapes_need_a_token_whose_key_may_get_metrics() {
    let server = start().await;
    let (status, challenge, _) = scrape(&server, None).await;
    assert_eq!((status, challenge.as_deref()), (401, Some("Bearer")));
    let forged = teifs_iam::metrics_token(ACCESS_KEY, "not-the-secret", None);
    assert_eq!(scrape(&server, Some(&forged)).await.0, 401);
    let expired = teifs_iam::metrics_token(ACCESS_KEY, SECRET_KEY, Some(1));
    let (status, _, body) = scrape(&server, Some(&expired)).await;
    assert_eq!(status, 401);
    assert!(body.contains("expired"), "{body}");

    // A user may scrape when a policy allows `teifs:GetMetrics`, and not after their
    // key is deleted.
    let token_of = |name: &str, policy: Option<&str>| {
        server.iam.create_user(name, None, &[], None).unwrap();
        if let Some(policy) = policy {
            server
                .iam
                .put_inline(teifs_iam::Owner::User(name), "p", policy)
                .unwrap();
        }
        let key = server.iam.create_access_key(name).unwrap();
        (
            key.info.id.clone(),
            teifs_iam::metrics_token(&key.info.id, &key.secret, None),
        )
    };
    let (_, nobody) = token_of("nobody", None);
    let (status, challenge, _) = scrape(&server, Some(&nobody)).await;
    assert_eq!((status, challenge), (403, None));
    let (key, prometheus) = token_of(
        "prometheus",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"teifs:GetMetrics","Resource":"*"}]}"#,
        ),
    );
    assert_eq!(scrape(&server, Some(&prometheus)).await.0, 200);
    server.iam.delete_access_key("prometheus", &key).unwrap();
    assert_eq!(scrape(&server, Some(&prometheus)).await.0, 401);
}

#[tokio::test]
async fn public_metrics_need_no_token() {
    let server = start_with(|config| config.public_metrics = true).await;
    let (status, _, text) = scrape(&server, None).await;
    assert_eq!(status, 200);
    assert!(text.ends_with("# EOF\n"));
}

#[tokio::test]
async fn requests_are_counted_by_operation_status_and_error() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("metrics").send().await.unwrap();
    s3.put_object()
        .bucket("metrics")
        .key("k")
        .body(ByteStream::from(vec![7; 1000]))
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object()
        .bucket("metrics")
        .key("k")
        .send()
        .await
        .unwrap();
    assert_eq!(got.body.collect().await.unwrap().into_bytes().len(), 1000);
    let missing = s3.get_object().bucket("metrics").key("gone").send().await;
    assert!(missing.is_err());
    // A signature that doesn't verify is refused before any operation is known.
    let wrong = client(&server, "not-the-secret");
    assert!(wrong.list_buckets().send().await.is_err());
    // The admin API's endpoints are named by what they do.
    let admin = teifs_client::Client::new(
        &server.endpoint,
        ACCESS_KEY,
        teifs_client::Zeroizing::new(SECRET_KEY.into()),
    )
    .unwrap();
    admin.info().await.unwrap();

    let text = metrics_with(
        &server,
        &[
            (
                r#"teifs_s3_requests_total{api="PutObject",code="200"}"#,
                1.0,
            ),
            (
                r#"teifs_s3_requests_total{api="GetObject",code="200"}"#,
                1.0,
            ),
            (
                r#"teifs_s3_requests_total{api="GetObject",code="404"}"#,
                1.0,
            ),
            (
                r#"teifs_s3_errors_total{api="GetObject",error="NoSuchKey"}"#,
                1.0,
            ),
            (r#"teifs_s3_requests_total{api="unknown",code="403"}"#, 1.0),
            (
                r#"teifs_s3_errors_total{api="unknown",error="SignatureDoesNotMatch"}"#,
                1.0,
            ),
            (
                r#"teifs_s3_requests_total{api="GetServerInfo",code="200"}"#,
                1.0,
            ),
            (r#"teifs_s3_received_bytes_total{api="PutObject"}"#, 1000.0),
            // The object, and the missing one's error.
            (r#"teifs_s3_sent_bytes_total{api="GetObject"}"#, 1001.0),
        ],
    )
    .await;
    assert!(value(&text, r#"teifs_s3_ttfb_seconds_count{api="PutObject"}"#) >= Some(1.0));
    assert!(value(&text, r#"teifs_s3_duration_seconds_count{api="GetObject"}"#) >= Some(2.0));
    assert_eq!(value(&text, "teifs_s3_requests_inflight"), Some(0.0));
    assert!(text.contains(&format!(
        "teifs_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(value(&text, "teifs_drive_total_bytes") > Some(0.0));
    assert!(value(&text, "teifs_start_time_seconds") > Some(0.0));
    assert!(text.contains("teifs_job_steps_total{job="), "{text}");
}

#[tokio::test]
async fn every_answer_carries_its_request_id() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    let listed = s3.list_buckets().send().await.unwrap();
    let id = listed.request_id().unwrap();
    assert_eq!(id.len(), 16);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));

    // An error's body names the id its header does.
    let response = reqwest::get(format!("{}/nowhere", server.endpoint))
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let id = response.headers()["x-amz-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = response.text().await.unwrap();
    assert!(
        body.contains(&format!("<RequestId>{id}</RequestId></Error>")),
        "{body}"
    );
    let missing = s3.head_bucket().bucket("nowhere").send().await.unwrap_err();
    assert_eq!(missing.request_id().map(str::len), Some(16));
}

#[tokio::test]
async fn a_client_that_leaves_early_is_counted_as_canceled() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server = start_with(|config| config.public_metrics = true).await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("big").send().await.unwrap();
    s3.put_object()
        .bucket("big")
        .key("k")
        .body(ByteStream::from(vec![0; 32 << 20]))
        .send()
        .await
        .unwrap();
    let got = s3.get_object().bucket("big").key("k").send().await.unwrap();
    assert_eq!(
        got.body.collect().await.unwrap().into_bytes().len(),
        32 << 20
    );
    // Nothing is canceled by a client that reads what it asked for.
    let text = metrics_with(
        &server,
        &[(
            r#"teifs_s3_requests_total{api="GetObject",code="200"}"#,
            1.0,
        )],
    )
    .await;
    assert_eq!(
        value(&text, r#"teifs_s3_canceled_total{api="GetObject"}"#),
        None
    );

    // A presigned GET whose reader goes after the first bytes.
    let link = s3
        .get_object()
        .bucket("big")
        .key("k")
        .presigned(
            aws_sdk_s3::presigning::PresigningConfig::expires_in(Duration::from_secs(60)).unwrap(),
        )
        .await
        .unwrap();
    let address = server.endpoint.trim_start_matches("http://");
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let path = link.uri().split_once(address).unwrap().1;
    let head = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\n\r\n");
    socket.write_all(head.as_bytes()).await.unwrap();
    let mut first = [0; 1024];
    assert!(socket.read(&mut first).await.unwrap() > 0);
    drop(socket);
    metrics_with(
        &server,
        &[(r#"teifs_s3_canceled_total{api="GetObject"}"#, 1.0)],
    )
    .await;
}

/// What the drive holds, in total and (asked for) by bucket, and what the scrub found.
#[tokio::test]
async fn usage_is_in_the_metrics_and_by_bucket_when_asked() {
    let server = start_with(|config| config.public_metrics = true).await;
    let s3 = client(&server, SECRET_KEY);
    for bucket in ["one", "two"] {
        s3.create_bucket().bucket(bucket).send().await.unwrap();
    }
    for (bucket, key, body) in [("one", "a", "hello"), ("one", "b", "hi"), ("two", "c", "x")] {
        s3.put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(body.as_bytes()))
            .send()
            .await
            .unwrap();
    }
    let (_, _, text) = scrape(&server, None).await;
    assert_eq!(value(&text, "teifs_buckets"), Some(2.0), "{text}");
    assert_eq!(value(&text, "teifs_usage_objects"), Some(3.0));
    assert_eq!(value(&text, "teifs_usage_versions"), Some(3.0));
    assert_eq!(value(&text, "teifs_usage_delete_markers"), Some(0.0));
    assert_eq!(value(&text, "teifs_usage_stored_bytes"), Some(8.0));
    assert!(!text.contains("teifs_bucket_"), "by bucket only when asked");
    assert!(text.trim_end().ends_with("# EOF"));

    let by_bucket = reqwest::get(format!("{}{METRICS_PATH}?buckets=1", server.endpoint))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        value(&by_bucket, "teifs_bucket_objects{bucket=\"one\"}"),
        Some(2.0),
        "{by_bucket}"
    );
    assert_eq!(
        value(&by_bucket, "teifs_bucket_stored_bytes{bucket=\"one\"}"),
        Some(7.0)
    );
    assert_eq!(
        value(&by_bucket, "teifs_bucket_stored_bytes{bucket=\"two\"}"),
        Some(1.0)
    );
    assert_eq!(by_bucket.matches("# EOF").count(), 1);
}

/// Where reads and writes spend their time: waiting for the KMS, the commit lock, the
/// disk.
#[tokio::test]
async fn reads_and_writes_are_timed_by_stage() {
    let server = start_with(|config| {
        config.public_metrics = true;
        config.default_layout = teifs_store::Layout::Object;
    })
    .await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("timed").send().await.unwrap();
    // Big enough for a data file of its own (and its sync).
    s3.put_object()
        .bucket("timed")
        .key("a")
        .body(ByteStream::from(vec![b'x'; 200 * 1024]))
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object()
        .bucket("timed")
        .key("a")
        .send()
        .await
        .unwrap();
    got.body.collect().await.unwrap();
    let (_, _, text) = scrape(&server, None).await;
    // New objects are encrypted (SSE-S3), so both need a data key.
    for (op, stage) in [
        ("write", "key"),
        ("write", "lock"),
        ("write", "sync"),
        ("write", "commit"),
        ("read", "locate"),
        ("read", "key"),
    ] {
        let series = format!("teifs_store_stage_seconds_count{{op=\"{op}\",stage=\"{stage}\"}}");
        assert!(
            value(&text, &series).is_some_and(|n| n >= 1.0),
            "{series} in {text}"
        );
    }
}

/// Puts a metrics configuration on `bucket`.
async fn measure(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    id: &str,
    filter: Option<aws_sdk_s3::types::MetricsFilter>,
) {
    let config = aws_sdk_s3::types::MetricsConfiguration::builder()
        .id(id)
        .set_filter(filter)
        .build()
        .unwrap();
    s3.put_bucket_metrics_configuration()
        .bucket(bucket)
        .id(id)
        .metrics_configuration(config)
        .send()
        .await
        .unwrap();
}

/// A bucket's request metrics series `metric` for configuration `id`.
fn of(metric: &str, bucket: &str, id: &str) -> String {
    format!("teifs_request_metrics_{metric}{{bucket=\"{bucket}\",filter_id=\"{id}\"}}")
}

#[tokio::test]
async fn buckets_request_metrics_count_what_each_configuration_matches() {
    use aws_sdk_s3::types::{Delete, MetricsFilter, ObjectIdentifier, Tag};
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("measured").send().await.unwrap();
    s3.create_bucket().bucket("other").send().await.unwrap();
    // Nothing is watched before a bucket has a configuration.
    s3.put_object()
        .bucket("measured")
        .key("early")
        .send()
        .await
        .unwrap();
    measure(&s3, "measured", "EntireBucket", None).await;
    measure(
        &s3,
        "measured",
        "docs",
        Some(MetricsFilter::Prefix("docs/".to_owned())),
    )
    .await;
    let red = Tag::builder().key("team").value("red").build().unwrap();
    measure(&s3, "measured", "red", Some(MetricsFilter::Tag(red))).await;
    s3.put_object()
        .bucket("measured")
        .key("docs/a")
        .tagging("team=red")
        .body(ByteStream::from(vec![1; 100]))
        .send()
        .await
        .unwrap();
    let got = s3
        .get_object()
        .bucket("measured")
        .key("docs/a")
        .send()
        .await
        .unwrap();
    assert_eq!(got.body.collect().await.unwrap().into_bytes().len(), 100);
    assert!(
        s3.get_object()
            .bucket("measured")
            .key("docs/missing")
            .send()
            .await
            .is_err()
    );
    s3.list_objects_v2()
        .bucket("measured")
        .send()
        .await
        .unwrap();
    s3.list_objects_v2().bucket("other").send().await.unwrap();
    let early = ObjectIdentifier::builder().key("early").build().unwrap();
    let delete = Delete::builder().objects(early).build().unwrap();
    s3.delete_objects()
        .bucket("measured")
        .delete(delete)
        .send()
        .await
        .unwrap();
    s3.head_object()
        .bucket("measured")
        .key("docs/a")
        .send()
        .await
        .unwrap();

    // The worker counts in order, so the last request seen means every one was.
    let text = metrics_with(
        &server,
        &[(&of("head_requests_total", "measured", "red"), 1.0)],
    )
    .await;
    let count = |metric: &str, id: &str| value(&text, &of(metric, "measured", id));
    for (metric, id, expected) in [
        ("put_requests_total", "docs", Some(1.0)),
        ("put_requests_total", "red", Some(1.0)),
        ("get_requests_total", "docs", Some(2.0)),
        ("get_requests_total", "red", Some(1.0)),
        ("head_requests_total", "docs", Some(1.0)),
        ("list_requests_total", "EntireBucket", Some(1.0)),
        ("list_requests_total", "docs", None),
        ("delete_requests_total", "EntireBucket", Some(1.0)),
        ("delete_requests_total", "docs", None),
        ("all_requests_total", "docs", Some(4.0)),
        ("all_requests_total", "red", Some(3.0)),
        ("4xx_errors_total", "docs", Some(1.0)),
        ("4xx_errors_total", "red", None),
        ("uploaded_bytes_total", "docs", Some(100.0)),
        ("first_byte_latency_seconds_count", "docs", Some(4.0)),
        ("total_request_latency_seconds_count", "red", Some(3.0)),
    ] {
        assert_eq!(count(metric, id), expected, "{metric} {id}\n{text}");
    }
    // The object, and the missing one's error.
    assert!(count("downloaded_bytes_total", "docs") > Some(100.0));
    // Configurations put after watching starts count their own puts' successors only:
    // early's put came before any.
    assert!(count("all_requests_total", "EntireBucket") >= Some(8.0));
    assert_eq!(count("put_requests_total", "EntireBucket"), Some(1.0));
    assert!(!text.contains("bucket=\"other\""), "{text}");
    assert_eq!(
        value(&text, "teifs_request_metrics_dropped_total"),
        Some(0.0)
    );
}

#[tokio::test]
async fn request_metrics_are_watched_from_the_start_after_a_restart() {
    let (dir, keys) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let run = || {
        let config = common::config(dir.path(), keys.path());
        async move {
            let server = teifs_server::Server::bind(config).await.unwrap();
            let endpoint = format!("http://{}", server.local_addr().unwrap());
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let running = tokio::spawn(server.run(async {
                let _ = stopped.await;
            }));
            (endpoint, stop, running)
        }
    };
    let (endpoint, stop, running) = run().await;
    let s3 = common::client_at(&endpoint, ACCESS_KEY, SECRET_KEY);
    s3.create_bucket().bucket("measured").send().await.unwrap();
    measure(&s3, "measured", "all", None).await;
    drop(stop);
    running.await.unwrap();

    let (endpoint, _stop, _running) = run().await;
    let s3 = common::client_at(&endpoint, ACCESS_KEY, SECRET_KEY);
    s3.head_bucket().bucket("measured").send().await.unwrap();
    let token = teifs_iam::metrics_token(ACCESS_KEY, SECRET_KEY, None);
    let series = of("all_requests_total", "measured", "all");
    for _ in 0..100 {
        let text = reqwest::Client::new()
            .get(format!("{endpoint}{METRICS_PATH}"))
            .bearer_auth(token.as_str())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if let Some(count) = value(&text, &series) {
            assert!((count - 1.0).abs() < f64::EPSILON, "{text}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the request was never counted");
}

#[tokio::test]
async fn an_imported_metrics_configuration_starts_watching() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("imported").send().await.unwrap();
    let admin = teifs_client::Client::new(
        &server.endpoint,
        ACCESS_KEY,
        teifs_client::Zeroizing::new(SECRET_KEY.into()),
    )
    .unwrap();
    let mut export = admin.export_buckets(Some("imported")).await.unwrap();
    export.buckets[0].settings.insert(
        "configurations".to_owned(),
        serde_json::json!({"metrics": {"all": {}}}),
    );
    admin.import_buckets(&export).await.unwrap();
    s3.head_bucket().bucket("imported").send().await.unwrap();
    metrics_with(
        &server,
        &[(&of("all_requests_total", "imported", "all"), 1.0)],
    )
    .await;
}
