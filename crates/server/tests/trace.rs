//! Live traces: the requests a server answers, as their audit entries, to an admin
//! watching; filtered on the server, without secrets, and ended when the server stops.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start};
use teifs_client::{AuditEntry, Trace, TraceFilter, Zeroizing};

fn admin(server: &Server) -> teifs_client::Client {
    teifs_client::Client::new(
        &server.endpoint,
        ACCESS_KEY,
        Zeroizing::new(SECRET_KEY.into()),
    )
    .unwrap()
}

/// The trace's next entry, within a few seconds.
async fn next(trace: &mut Trace) -> AuditEntry {
    tokio::time::timeout(Duration::from_secs(10), trace.next())
        .await
        .expect("an entry within 10 s")
        .unwrap()
        .expect("the trace goes on")
}

#[tokio::test]
async fn a_trace_shows_the_requests_its_filter_does_as_they_happen() {
    let server = start().await;
    let admin = admin(&server);
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("other").send().await.unwrap();
    let mut everything = admin.trace(&TraceFilter::default()).await.unwrap();
    let on_bucket = TraceFilter {
        bucket: Some("traced".into()),
        ..TraceFilter::default()
    };
    let mut traced = admin.trace(&on_bucket).await.unwrap();
    let errors = TraceFilter {
        errors: true,
        ..TraceFilter::default()
    };
    let mut failed = admin.trace(&errors).await.unwrap();

    s3.create_bucket().bucket("traced").send().await.unwrap();
    s3.list_objects_v2().bucket("other").send().await.unwrap();
    s3.put_object()
        .bucket("traced")
        .key("dir/a.txt")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap();
    s3.get_object()
        .bucket("traced")
        .key("gone")
        .send()
        .await
        .unwrap_err();

    let names = |entries: &[AuditEntry]| {
        entries
            .iter()
            .map(|e| e.api.name.clone())
            .collect::<Vec<_>>()
    };
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(next(&mut traced).await);
    }
    assert_eq!(names(&seen), ["CreateBucket", "PutObject", "GetObject"]);
    let put = &seen[1];
    assert_eq!(
        (
            put.api.object.as_str(),
            put.api.status_code,
            put.access_key.as_str()
        ),
        ("dir/a.txt", 200, ACCESS_KEY)
    );
    assert_eq!(put.request_header["authorization"], "REDACTED");
    assert_eq!(
        (seen[2].api.status_code, seen[2].error.as_str()),
        (404, "NoSuchKey")
    );

    let mut all = Vec::new();
    for _ in 0..4 {
        all.push(next(&mut everything).await);
    }
    assert_eq!(
        names(&all),
        ["CreateBucket", "ListObjectsV2", "PutObject", "GetObject"]
    );
    assert_eq!(next(&mut failed).await.api.name, "GetObject");
}

#[tokio::test]
async fn unsigned_traces_are_refused() {
    let server = start().await;
    let url = format!("{}/.teifs/admin/v1/trace", server.endpoint);
    assert_eq!(reqwest::get(&url).await.unwrap().status(), 403);
}

#[tokio::test]
async fn traces_end_when_the_server_stops() {
    let server = start().await;
    let mut trace = admin(&server).trace(&TraceFilter::default()).await.unwrap();
    drop(server);
    // Well before the server would stop waiting for open requests (10 s).
    let end = tokio::time::timeout(Duration::from_secs(3), trace.next())
        .await
        .expect("the trace ends within 3 s");
    assert!(matches!(end, Ok(None)), "{end:?}");
}
