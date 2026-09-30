//! Listening for events (`MinIO`'s listen API, as `mc watch` uses it): one bucket's or
//! every bucket's, filtered on the server, with or without notification targets, and
//! allowed by policies.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

mod common;

use std::time::Duration;

use aws_sdk_s3::primitives::ByteStream;
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start};
use teifs_client::{EventRecord, Listen, ListenFilter, Zeroizing};

fn listener(server: &Server) -> teifs_client::Client {
    teifs_client::Client::new(
        &server.endpoint,
        ACCESS_KEY,
        Zeroizing::new(SECRET_KEY.into()),
    )
    .unwrap()
}

fn filter(events: &[&str], prefix: &str) -> ListenFilter {
    ListenFilter {
        events: events.iter().map(|&e| e.to_owned()).collect(),
        prefix: prefix.to_owned(),
        suffix: String::new(),
    }
}

/// The next event, within a few seconds.
async fn next(listen: &mut Listen) -> EventRecord {
    tokio::time::timeout(Duration::from_secs(10), listen.next())
        .await
        .expect("an event within 10 s")
        .unwrap()
        .expect("the answer goes on")
}

fn described(record: &EventRecord) -> (String, String, String) {
    (
        record.event_name.clone(),
        record.s3.bucket.name.clone(),
        record.s3.object.key.clone(),
    )
}

fn event(name: &str, bucket: &str, key: &str) -> (String, String, String) {
    (name.to_owned(), bucket.to_owned(), key.to_owned())
}

#[tokio::test]
async fn listeners_get_the_events_they_ask_for_as_they_happen() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    let listener = listener(&server);
    s3.create_bucket().bucket("photos").send().await.unwrap();
    s3.create_bucket().bucket("other").send().await.unwrap();
    let mut photos = listener
        .listen(Some("photos"), &filter(&["s3:ObjectCreated:*"], "a/"))
        .await
        .unwrap();
    let mut everywhere = listener
        .listen(
            None,
            &filter(
                &[
                    "s3:ObjectRemoved:*",
                    "s3:BucketCreated:*",
                    "s3:BucketRemoved:*",
                ],
                "",
            ),
        )
        .await
        .unwrap();

    for (bucket, key) in [("other", "a/1"), ("photos", "b/1"), ("photos", "a/1")] {
        s3.put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(b"hello"))
            .send()
            .await
            .unwrap();
    }
    let put = next(&mut photos).await;
    assert_eq!(described(&put), event("ObjectCreated:Put", "photos", "a/1"));
    assert_eq!(put.s3.object.size, Some(5));
    assert_eq!(put.s3.configuration_id, "Config");
    assert_eq!(put.user_identity.principal_id, ACCESS_KEY);

    s3.create_bucket().bucket("new").send().await.unwrap();
    s3.delete_object()
        .bucket("photos")
        .key("a/1")
        .send()
        .await
        .unwrap();
    s3.delete_bucket().bucket("new").send().await.unwrap();
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(described(&next(&mut everywhere).await));
    }
    assert_eq!(
        seen,
        [
            event("BucketCreated:*", "new", ""),
            event("ObjectRemoved:Delete", "photos", "a/1"),
            event("BucketRemoved:*", "new", ""),
        ]
    );
    // Nothing else reached the bucket's listener: its next event is a later one.
    s3.put_object()
        .bucket("photos")
        .key("a/2")
        .body(ByteStream::from_static(b""))
        .send()
        .await
        .unwrap();
    assert_eq!(next(&mut photos).await.s3.object.key, "a/2");
}

#[tokio::test]
async fn listening_is_allowed_by_policies_and_checked() {
    let server = start().await;
    let s3 = client(&server, SECRET_KEY);
    s3.create_bucket().bucket("public").send().await.unwrap();
    let url = |path: &str| format!("{}{path}?events=s3:ObjectCreated:*&ping=1", server.endpoint);
    let status = |path: &'static str| {
        let url = url(path);
        async move { reqwest::get(&url).await.unwrap().status().as_u16() }
    };
    assert_eq!(status("/public").await, 403, "unsigned, with no policy");
    assert_eq!(status("/").await, 403);

    s3.delete_public_access_block()
        .bucket("public")
        .send()
        .await
        .unwrap();
    s3.put_bucket_policy()
        .bucket("public")
        .policy(
            r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
                "Action": "s3:ListenBucketNotification", "Resource": "arn:aws:s3:::public"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let mut anyone = reqwest::get(&url("/public")).await.unwrap();
    assert_eq!(anyone.status(), 200);
    assert_eq!(anyone.headers()["content-type"], "text/event-stream");
    let ping = tokio::time::timeout(Duration::from_secs(5), anyone.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        &ping[..],
        b"{\"Records\":[]}\n",
        "the heartbeat, every ping"
    );
    assert_eq!(status("/").await, 403, "every bucket's needs a key");

    let listener = listener(&server);
    let refused = |bucket: Option<&'static str>, filter: ListenFilter| {
        let listener = listener.clone();
        async move {
            match listener.listen(bucket, &filter).await.unwrap_err() {
                teifs_client::ClientError::Api { status, code, .. } => (status, code),
                other => panic!("{other}"),
            }
        }
    };
    let created = filter(&["s3:ObjectCreated:*"], "");
    assert_eq!(
        refused(Some("missing"), created.clone()).await,
        (404, "NoSuchBucket".to_owned())
    );
    assert_eq!(
        refused(Some("public"), filter(&["s3:ObjectMoved:*"], "")).await,
        (400, "InvalidArgument".to_owned())
    );
    assert_eq!(
        refused(None, filter(&[], "")).await,
        (400, "InvalidArgument".to_owned())
    );
}

#[tokio::test]
async fn listening_ends_when_the_server_stops() {
    let server = start().await;
    let mut listen = listener(&server)
        .listen(None, &filter(&["s3:ObjectCreated:*"], ""))
        .await
        .unwrap();
    drop(server);
    let end = tokio::time::timeout(Duration::from_secs(3), listen.next())
        .await
        .expect("ended before the server stops waiting for open requests");
    assert!(matches!(end, Ok(None)), "{end:?}");
}
