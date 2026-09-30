use zeroize::Zeroizing;

use super::*;
use crate::testing::Receiver;

fn hook(receiver: &Receiver, id: &str) -> TargetConfig {
    let hook = Webhook::new(receiver.url(), Some(Zeroizing::new("t0ken".into()))).unwrap();
    TargetConfig::new(id, TargetKind::Webhook(hook)).unwrap()
}

fn events(arn: &TargetArn, range: std::ops::Range<u32>) -> Vec<(TargetArn, Vec<u8>)> {
    range
        .map(|n| (arn.clone(), format!("{{\"n\":{n}}}").into_bytes()))
        .collect()
}

fn bodies(receiver: &Receiver) -> Vec<String> {
    receiver.taken().into_iter().map(|post| post.body).collect()
}

/// Every event is sent, one per request with the token, in order, after a target that
/// failed takes them again.
#[tokio::test]
async fn events_are_sent_in_order_after_failures() {
    let receiver = Receiver::start(3).await;
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![hook(&receiver, "primary")],
    )
    .unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::primary:webhook").unwrap();
    assert!(notifier.has(&arn));
    notifier.queue(events(&arn, 0..5)).await.unwrap();
    notifier.queue(events(&arn, 5..8)).await.unwrap();
    let posts = receiver.posts(8).await;
    let expected: Vec<String> = (0..8).map(|n| format!("{{\"n\":{n}}}")).collect();
    assert_eq!(bodies(&receiver), expected);
    assert!(
        posts
            .iter()
            .all(|p| p.authorization == "Bearer t0ken" && p.content_type == "application/json")
    );
    // The receiver has the last event before the sender reads its answer and counts it.
    for _ in 0..500 {
        let stats = &notifier.stats()[0];
        if stats.sent == 8 && stats.queued == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stats = &notifier.stats()[0];
    assert_eq!(
        (stats.sent, stats.failed, stats.dropped, stats.queued),
        (8, 3, 0, 0)
    );
    assert!(stats.online);
    notifier.stop().await;
}

/// Events for a target that's down wait on the drive, and are sent after a restart;
/// what was sent isn't sent again.
#[tokio::test]
async fn waiting_events_survive_a_restart() {
    let receiver = Receiver::start(0).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.db");
    let notifier = Notifier::start(&path, vec![hook(&receiver, "primary")]).unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::primary:webhook").unwrap();
    notifier.queue(events(&arn, 0..2)).await.unwrap();
    receiver.posts(2).await;
    receiver.fail(usize::MAX);
    notifier.queue(events(&arn, 2..4)).await.unwrap();
    while receiver.tries() < 3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    notifier.stop().await;
    assert_eq!(notifier.stats()[0].queued, 2);
    assert!(!notifier.stats()[0].online);

    receiver.fail(0);
    let notifier = Notifier::start(&path, vec![hook(&receiver, "primary")]).unwrap();
    assert_eq!(notifier.stats()[0].queued, 2, "counted from the drive");
    receiver.posts(4).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let expected: Vec<String> = (0..4).map(|n| format!("{{\"n\":{n}}}")).collect();
    assert_eq!(bodies(&receiver), expected);
    notifier.stop().await;
}

/// A target with too many events waiting drops new ones, and counts them; an event for
/// a target the server doesn't have is skipped.
#[tokio::test]
async fn a_full_queue_drops_new_events() {
    let receiver = Receiver::start(usize::MAX).await;
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start_with_limit(
        &dir.path().join("events.db"),
        vec![hook(&receiver, "primary")],
        3,
    )
    .unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::primary:webhook").unwrap();
    let other = TargetArn::parse("arn:teifs:sqs::other:webhook").unwrap();
    notifier.queue(events(&arn, 0..5)).await.unwrap();
    notifier.queue(events(&other, 0..5)).await.unwrap();
    let stats = &notifier.stats()[0];
    assert_eq!((stats.queued, stats.dropped), (3, 2));
    notifier.stop().await;
}

#[test]
fn targets_are_named_as_arns_can_name_them() {
    let hook = Webhook::new("http://localhost/", None).unwrap();
    let target = TargetConfig::new("primary-1", TargetKind::Webhook(hook.clone())).unwrap();
    assert_eq!(target.arn().to_string(), "arn:teifs:sqs::primary-1:webhook");
    for bad in ["", "a:b", "a b", "ü"] {
        assert!(
            TargetConfig::new(bad, TargetKind::Webhook(hook.clone())).is_err(),
            "{bad}"
        );
    }
    assert!(Notifier::none().is_empty());
}

#[tokio::test]
async fn rules_name_targets_by_our_arns_or_a_queues_own() {
    let hook = Webhook::new("http://localhost/", None).unwrap();
    let sqs = Sqs::new(
        "https://sqs.eu-west-1.amazonaws.com/123456789012/orders",
        None,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![
            TargetConfig::new("hook", TargetKind::Webhook(hook)).unwrap(),
            TargetConfig::new("orders", TargetKind::Sqs(sqs)).unwrap(),
        ],
    )
    .unwrap();
    let resolved = |arn: &str| notifier.resolve(arn).map(|t| t.to_string());
    assert_eq!(
        resolved("arn:minio:sqs::hook:webhook").as_deref(),
        Some("arn:teifs:sqs::hook:webhook")
    );
    for arn in [
        "arn:teifs:sqs::orders:sqs",
        "arn:aws:sqs:eu-west-1:123456789012:orders",
    ] {
        assert_eq!(
            resolved(arn).as_deref(),
            Some("arn:teifs:sqs::orders:sqs"),
            "{arn}"
        );
    }
    for unknown in [
        "arn:teifs:sqs::other:webhook",
        "arn:teifs:sqs::hook:sqs",
        "arn:aws:sqs:eu-west-1:123456789012:other",
        "arn:aws:sns:eu-west-1:123456789012:orders",
        "",
    ] {
        assert_eq!(resolved(unknown), None, "{unknown}");
    }
    notifier.stop().await;
}

/// An event as the server queues it: `name` on `BUCKET/KEY`.
pub(crate) fn message(name: &str, key: &str) -> Vec<u8> {
    let (bucket, object) = key.split_once('/').unwrap();
    serde_json::to_vec(&serde_json::json!({
        "EventName": name, "Key": key,
        "Records": [{
            "eventVersion": "2.6", "eventSource": "aws:s3", "awsRegion": "us-east-1",
            "eventTime": "2026-09-30T12:00:00.000Z",
            "eventName": name.trim_start_matches("s3:"),
            "userIdentity": {"principalId": "key"},
            "requestParameters": {"sourceIPAddress": "127.0.0.1"},
            "responseElements": {"x-amz-request-id": "1", "x-amz-id-2": "drive"},
            "s3": {
                "s3SchemaVersion": "1.0", "configurationId": "rule",
                "bucket": {"name": bucket, "ownerIdentity": {"principalId": "o"},
                           "arn": format!("arn:aws:s3:::{bucket}")},
                "object": {"key": object, "sequencer": "1"}
            }
        }]
    }))
    .unwrap()
}

/// Elasticsearch targets: the index is made when missing, and each event is a document,
/// one per object (removed with it) or one per event.
#[tokio::test]
async fn elasticsearch_keeps_a_document_per_object_or_per_event() {
    let receiver = Receiver::start(0).await;
    let base = receiver.url().to_owned();
    let mut objects = Elasticsearch::new(&base, "objects", Format::Namespace).unwrap();
    objects.api_key = Some(Zeroizing::new("k3y".into()));
    let mut log = Elasticsearch::new(&base, "log", Format::Access).unwrap();
    log.username = Some("elastic".into());
    log.password = Some(Zeroizing::new("pw".into()));
    receiver.missing("/hook/objects");
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![
            TargetConfig::new("objects", TargetKind::Elasticsearch(objects)).unwrap(),
            TargetConfig::new("log", TargetKind::Elasticsearch(log)).unwrap(),
        ],
    )
    .unwrap();
    let (objects, log) = (
        TargetArn::parse("arn:teifs:sqs::objects:elasticsearch").unwrap(),
        TargetArn::parse("arn:teifs:sqs::log:elasticsearch").unwrap(),
    );
    notifier.send_now(&objects, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a b.jpg");
    let delete = message("s3:ObjectRemoved:Delete", "photos/a b.jpg");
    notifier
        .queue(vec![
            (objects.clone(), put.clone()),
            (objects, delete),
            (log.clone(), put),
        ])
        .await
        .unwrap();
    let taken = receiver.posts(5).await;
    let id = elasticsearch::document_id("photos/a b.jpg");
    let requests: Vec<(String, String)> = taken
        .iter()
        .map(|p| (p.method.clone(), p.path.clone()))
        .collect();
    let objects_requests: Vec<_> = requests
        .iter()
        .filter(|(_, p)| p.contains("/objects"))
        .cloned()
        .collect();
    assert_eq!(
        objects_requests,
        [
            ("PUT".to_owned(), "/hook/objects".to_owned()),
            ("PUT".to_owned(), format!("/hook/objects/_doc/{id}")),
            ("DELETE".to_owned(), format!("/hook/objects/_doc/{id}")),
        ],
        "made, written, removed"
    );
    let log_requests: Vec<_> = taken.iter().filter(|p| p.path.contains("/log")).collect();
    assert_eq!(
        log_requests
            .iter()
            .map(|p| (p.method.as_str(), p.path.as_str()))
            .collect::<Vec<_>>(),
        [("HEAD", "/hook/log"), ("POST", "/hook/log/_doc")]
    );
    let document: serde_json::Value = serde_json::from_str(&log_requests[1].body).unwrap();
    assert_eq!(document["Records"][0]["s3"]["object"]["key"], "a b.jpg");
    assert_eq!(document.as_object().unwrap().len(), 1, "only Records");
    assert_eq!(log_requests[1].authorization, "Basic ZWxhc3RpYzpwdw==");
    assert!(
        taken
            .iter()
            .filter(|p| p.path.contains("/objects"))
            .all(|p| p.authorization == "ApiKey k3y")
    );
    assert!(
        !taken.iter().any(|p| p.body == "test"),
        "no test document is written"
    );
    notifier.stop().await;
}

/// Redis targets: a hash with a field per object (removed with it), or a list with an
/// entry per event; the password and database are used, and a key of the wrong type is
/// refused.
#[tokio::test]
async fn redis_keeps_a_field_per_object_or_an_entry_per_event() {
    use crate::testing::RedisServer;
    let server = RedisServer::start("none", Some("pw")).await;
    let mut objects = Redis::new(server.address(), "objects", Format::Namespace).unwrap();
    objects.password = Some(Zeroizing::new("pw".into()));
    objects.db = Some(2);
    let mut log = Redis::new(server.address(), "log", Format::Access).unwrap();
    log.password = Some(Zeroizing::new("pw".into()));
    log.user = Some("teifs".into());
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![
            TargetConfig::new("objects", TargetKind::Redis(objects)).unwrap(),
            TargetConfig::new("log", TargetKind::Redis(log)).unwrap(),
        ],
    )
    .unwrap();
    let objects = TargetArn::parse("arn:teifs:sqs::objects:redis").unwrap();
    let log = TargetArn::parse("arn:teifs:sqs::log:redis").unwrap();
    notifier.send_now(&objects, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    notifier
        .queue(vec![
            (objects.clone(), put.clone()),
            (objects, message("s3:ObjectRemoved:Delete", "photos/a.jpg")),
        ])
        .await
        .unwrap();
    notifier.queue(vec![(log, put)]).await.unwrap();
    let commands = server.commands(9).await;
    let names: Vec<String> = commands
        .iter()
        .map(|c| c[..2.min(c.len())].join(" "))
        .collect();
    // The test's connection, kept for the events; the log's own.
    let objects_commands: Vec<&String> = names
        .iter()
        .filter(|n| n.contains("objects") || n.starts_with("SELECT") || n.starts_with("PING"))
        .collect();
    assert_eq!(
        objects_commands,
        [
            "SELECT 2",
            "TYPE objects",
            "PING",
            "HSET objects",
            "HDEL objects"
        ]
    );
    let hset = commands.iter().find(|c| c[0] == "HSET").unwrap();
    assert_eq!(hset[2], "photos/a.jpg");
    let value: serde_json::Value = serde_json::from_str(&hset[3]).unwrap();
    assert_eq!(value["Records"][0]["s3"]["object"]["key"], "a.jpg");
    let rpush = commands.iter().find(|c| c[0] == "RPUSH").unwrap();
    let entry: serde_json::Value = serde_json::from_str(&rpush[2]).unwrap();
    assert_eq!(entry[0]["EventTime"], "2026-09-30T12:00:00.000Z");
    assert_eq!(entry[0]["Event"][0]["eventName"], "ObjectCreated:Put");
    assert!(names.contains(&"TYPE log".to_owned()));
    notifier.stop().await;

    // A key that holds something else, or a wrong password, fails the test.
    let hash = RedisServer::start("hash", None).await;
    let wrong = Redis::new(hash.address(), "k", Format::Access).unwrap();
    let err = wrong.test().await.unwrap_err();
    assert!(
        err.contains("holds a hash") && err.contains("needs a list"),
        "{err}"
    );
    let mut bad = Redis::new(server.address(), "k", Format::Access).unwrap();
    bad.password = Some(Zeroizing::new("nope".into()));
    assert!(bad.test().await.unwrap_err().contains("WRONGPASS"));
}

/// A certificate authority for tests: servers for `localhost` and clients it signs.
struct TestCa {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}

impl TestCa {
    fn new() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    /// A certificate it signs for `names` (a client's when `client`), and its key.
    fn issue(&self, names: &[&str], client: bool) -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|&n| n.to_owned()).collect::<Vec<_>>())
                .unwrap();
        if client {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        (params.signed_by(&key, &issuer).unwrap(), key)
    }

    /// A client's certificate and key, as PEM files hold them.
    fn client_pem(&self) -> (String, String) {
        let (cert, key) = self.issue(&["teifs"], true);
        (cert.pem(), key.serialize_pem())
    }

    /// A TLS acceptor for `localhost`; with `clients`, it wants a certificate this CA
    /// signed from each client.
    fn acceptor(&self, clients: bool) -> tokio_rustls::TlsAcceptor {
        use rustls::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject,
        };
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let (cert, key) = self.issue(&["localhost"], false);
        let builder = rustls::ServerConfig::builder_with_provider(std::sync::Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = if clients {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from_pem_slice(self.pem.as_bytes()).unwrap())
                .unwrap();
            let verifier =
                rustls::server::WebPkiClientVerifier::builder_with_provider(roots.into(), provider)
                    .build()
                    .unwrap();
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let config = builder
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
    }
}

/// A TLS acceptor for `localhost`, and the PEM of the CA that signed its certificate.
fn test_tls() -> (tokio_rustls::TlsAcceptor, String) {
    let ca = TestCa::new();
    (ca.acceptor(false), ca.pem)
}

/// A TLS terminator for `localhost` in front of `plain`, and the PEM of the CA that
/// signed its certificate.
async fn tls_in_front_of(plain: &str) -> (String, String) {
    let (acceptor, ca_pem) = test_tls();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let plain = plain.to_owned();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, plain) = (acceptor.clone(), plain.clone());
            tokio::spawn(async move {
                let Ok(mut secured) = acceptor.accept(stream).await else {
                    return;
                };
                let mut inner = tokio::net::TcpStream::connect(plain).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut secured, &mut inner).await;
            });
        }
    });
    (format!("localhost:{port}"), ca_pem)
}

/// Redis over TLS: the server is verified with the operator's CA, and one the CA didn't
/// sign is refused.
#[tokio::test]
async fn redis_is_reached_over_tls() {
    use crate::testing::RedisServer;
    let server = RedisServer::start("none", None).await;
    let (address, ca_pem) = tls_in_front_of(server.address()).await;
    let mut redis = Redis::new(&address, "objects", Format::Namespace).unwrap();
    redis.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert!(redis.shown().starts_with("rediss://"), "{}", redis.shown());
    redis.test().await.unwrap();
    assert!(
        server
            .commands(2)
            .await
            .contains(&vec!["TYPE".into(), "objects".into()])
    );

    // The system's trust store doesn't know the test CA.
    redis.tls = Some(tls_config(None, None).unwrap());
    let err = redis.test().await.unwrap_err();
    assert!(err.contains("TLS failed"), "{err}");
    // Nor does the plain server speak TLS.
    let mut plain = Redis::new(server.address(), "objects", Format::Namespace).unwrap();
    plain.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert!(plain.test().await.is_err());
}

/// NSQ targets: each event published to the topic as a webhook gets it, heartbeats
/// answered.
#[tokio::test]
async fn nsq_publishes_each_event() {
    use crate::testing::NsqServer;
    let server = NsqServer::start().await;
    let nsq = Nsq::new(server.address(), "s3-events").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![TargetConfig::new("queue", TargetKind::Nsq(nsq)).unwrap()],
    )
    .unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::queue:nsq").unwrap();
    notifier.send_now(&arn, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    notifier
        .queue(vec![(arn.clone(), put.clone()), (arn, put.clone())])
        .await
        .unwrap();
    let published = server.published(2).await;
    assert_eq!(published.len(), 2, "the test publishes nothing");
    assert_eq!(published[0].0, "s3-events");
    assert_eq!(published[0].1.as_bytes(), &put[..]);
    // IDENTIFY's and each PUB's heartbeat, the last answered after its PUB was kept.
    for _ in 0..100 {
        if server.nops() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.nops(), 3);
    notifier.stop().await;

    let nowhere = Nsq::new("127.0.0.1:1", "t").unwrap();
    assert!(nowhere.test().await.unwrap_err().contains("can't connect"));
}

/// NATS targets: each event published to the subject, the server's `PONG` confirming
/// it; the credentials sent; a connection the server closed is made again at once.
#[tokio::test]
async fn nats_publishes_each_event() {
    use crate::testing::{NatsServer, NatsSetup};
    let server = NatsServer::start(NatsSetup {
        user: Some(("teifs".into(), "pw".into())),
        ..NatsSetup::default()
    })
    .await;
    let mut nats = Nats::new(server.address(), "s3.events").unwrap();
    nats.user = Some("teifs".into());
    nats.password = Some(Zeroizing::new("pw".into()));
    assert!(!format!("{nats:?}").contains("pw"));
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(
        &dir.path().join("events.db"),
        vec![TargetConfig::new("bus", TargetKind::Nats(nats.clone())).unwrap()],
    )
    .unwrap();
    let arn = TargetArn::parse("arn:teifs:sqs::bus:nats").unwrap();
    notifier.send_now(&arn, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    notifier
        .queue(vec![(arn.clone(), put.clone()), (arn, put.clone())])
        .await
        .unwrap();
    let published = server.published(2).await;
    assert_eq!(published.len(), 2, "the test publishes nothing");
    assert!(
        published
            .iter()
            .all(|p| p.subject == "s3.events" && p.reply.is_none())
    );
    assert_eq!(published[0].body.as_bytes(), put);
    let connect = &server.connects()[0];
    assert_eq!(
        (&connect["user"], &connect["name"], &connect["echo"]),
        (&"teifs".into(), &"teifs".into(), &false.into())
    );
    notifier.stop().await;

    // The server closes a connection kept idle; the next event makes another.
    nats.send(b"{}").await.unwrap();
    server.kick();
    tokio::time::sleep(Duration::from_millis(50)).await;
    nats.send(b"{\"after\":1}").await.unwrap();
    assert_eq!(server.published(4).await[3].body, "{\"after\":1}");

    // Events larger than the server takes, or a wrong password, fail.
    let err = nats.send(&[b'x'; 5000]).await.unwrap_err();
    assert!(
        err.contains("larger than the server takes (4096 bytes)"),
        "{err}"
    );
    nats.password = Some(Zeroizing::new("nope".into()));
    let err = nats.test().await.unwrap_err();
    assert!(err.contains("Authorization Violation"), "{err}");
}

/// NATS `JetStream`: each event acknowledged by the stream that takes the subject, an
/// event sent again dropped as a duplicate by its id; a subject no stream takes, or no
/// `JetStream`, fails its test.
#[tokio::test]
async fn nats_jetstream_acknowledges_each_event() {
    use crate::testing::{NatsServer, NatsSetup};
    let server = NatsServer::start(NatsSetup {
        token: Some("t0ken".into()),
        streams: Some(vec![("EVENTS".into(), "s3.events".into())]),
        headers: true,
        ..NatsSetup::default()
    })
    .await;
    let mut nats = Nats::new(server.address(), "s3.events").unwrap();
    nats.jetstream = true;
    nats.token = Some(Zeroizing::new("t0ken".into()));
    assert!(nats.shown().ends_with("(JetStream)"));
    nats.test().await.unwrap();
    nats.send(b"{\"n\":1}").await.unwrap();
    nats.send(b"{\"n\":1}").await.unwrap();
    let published = server.published(2).await;
    assert!(
        published[0]
            .reply
            .as_deref()
            .is_some_and(|r| r.starts_with("_INBOX."))
    );
    assert!(published[0].id.is_some(), "{published:?}");
    assert_eq!(
        published[0].id, published[1].id,
        "the same event, the same id"
    );
    assert_eq!(server.connects()[0]["auth_token"], "t0ken");
    assert_eq!(server.connects()[0]["no_responders"], true);

    let mut elsewhere = Nats::new(server.address(), "other").unwrap();
    elsewhere.jetstream = true;
    elsewhere.token = nats.token.clone();
    let err = elsewhere.test().await.unwrap_err();
    assert!(err.contains("no JetStream stream takes `other`"), "{err}");
    let err = elsewhere.send(b"{}").await.unwrap_err();
    assert!(err.contains("no JetStream stream takes `other`"), "{err}");

    let plain = NatsServer::start(NatsSetup {
        headers: true,
        ..NatsSetup::default()
    })
    .await;
    let mut nats = Nats::new(plain.address(), "s3.events").unwrap();
    nats.jetstream = true;
    let err = nats.test().await.unwrap_err();
    assert!(err.contains("JetStream isn't enabled"), "{err}");
}

/// NATS nkeys: the server's nonce signed by the seed, sent with its public key, or
/// with the user JWT of a `.creds` file; another user's key is refused.
#[tokio::test]
async fn nats_signs_its_nonce_with_nkeys() {
    use crate::{
        nkey::tests::{USER_BYTE, encode_seed},
        testing::{
            NKEY_JWT as JWT, NKEY_PUBLIC as PUBLIC, NKEY_SEED as SEED, NatsServer, NatsSetup, creds,
        },
    };
    let server = NatsServer::start(NatsSetup {
        nkeys: vec![PUBLIC.into()],
        ..NatsSetup::default()
    })
    .await;
    let mut nats = Nats::new(server.address(), "s3").unwrap();
    nats.key = Some(Arc::new(UserKey::parse(SEED).unwrap()));
    nats.test().await.unwrap();
    nats.key = Some(Arc::new(UserKey::parse(&creds()).unwrap()));
    nats.test().await.unwrap();
    let connects = server.connects();
    assert_eq!(
        (connects[0]["nkey"].as_str(), connects[0].get("jwt")),
        (Some(PUBLIC), None)
    );
    assert_eq!(
        (connects[1]["jwt"].as_str(), connects[1].get("nkey")),
        (Some(JWT), None)
    );
    assert!(connects.iter().all(|c| c["sig"].is_string()));

    let other = UserKey::parse(&encode_seed(USER_BYTE, &[7; 32])).unwrap();
    nats.key = Some(Arc::new(other));
    let err = nats.test().await.unwrap_err();
    assert!(err.contains("Authorization Violation"), "{err}");
    // A server without nkeys sends no nonce to sign.
    let plain = NatsServer::start(NatsSetup::default()).await;
    let mut nats = Nats::new(plain.address(), "s3").unwrap();
    nats.key = Some(Arc::new(UserKey::parse(SEED).unwrap()));
    assert!(nats.test().await.unwrap_err().contains("no nonce"));
}

/// NATS over TLS: after `INFO` when the server requires it, or first; the server
/// verified with the operator's CA.
#[tokio::test]
async fn nats_is_reached_over_tls() {
    use crate::testing::{NatsServer, NatsSetup};
    let (acceptor, ca_pem) = test_tls();
    let tls = tls_config(Some(ca_pem.as_bytes()), None).unwrap();
    for first in [false, true] {
        let server = NatsServer::start(NatsSetup {
            tls: Some((acceptor.clone(), first)),
            ..NatsSetup::default()
        })
        .await;
        let port = server.address().rsplit_once(':').unwrap().1;
        let mut nats = Nats::new(&format!("localhost:{port}"), "s3").unwrap();
        if !first {
            let err = nats.test().await.unwrap_err();
            assert!(err.contains("requires TLS"), "{err}");
        }
        nats.tls = Some(Arc::clone(&tls));
        nats.tls_first = first;
        assert!(nats.shown().starts_with("tls://"));
        nats.test().await.unwrap();
        nats.send(b"{}").await.unwrap();
        assert_eq!(server.published(1).await[0].body, "{}");
        assert_eq!(server.connects()[0]["tls_required"], true);
    }
}

/// Client certificates: a server that wants one gets the certificate and key given,
/// and refuses a client without one.
#[tokio::test]
async fn targets_show_their_client_certificate() {
    use crate::testing::{NatsServer, NatsSetup};
    let ca = TestCa::new();
    let server = NatsServer::start(NatsSetup {
        tls: Some((ca.acceptor(true), false)),
        ..NatsSetup::default()
    })
    .await;
    let port = server.address().rsplit_once(':').unwrap().1;
    let mut nats = Nats::new(&format!("localhost:{port}"), "s3").unwrap();
    nats.tls = Some(tls_config(Some(ca.pem.as_bytes()), None).unwrap());
    assert!(nats.test().await.is_err(), "no client certificate");
    let (cert, key) = ca.client_pem();
    nats.tls = Some(
        tls_config(
            Some(ca.pem.as_bytes()),
            Some((cert.as_bytes(), key.as_bytes())),
        )
        .unwrap(),
    );
    nats.test().await.unwrap();
    nats.send(b"{}").await.unwrap();
    assert_eq!(server.published(1).await[0].body, "{}");

    // Files that aren't a certificate and its key are refused.
    let other = TestCa::new().client_pem();
    for (chain, key) in [
        ("", key.as_str()),
        (cert.as_str(), ""),
        (cert.as_str(), other.1.as_str()),
    ] {
        let identity = Some((chain.as_bytes(), key.as_bytes()));
        assert!(tls_config(None, identity).is_err(), "{chain:.20} {key:.20}");
    }
}

/// MQTT targets: each event published to the topic with its quality of service and
/// acknowledged as that asks, with a clean session and the user and password; over TLS.
#[tokio::test]
async fn mqtt_publishes_with_each_quality_of_service() {
    use crate::testing::MqttServer;
    let server = MqttServer::start(Some(("teifs", "pw"))).await;
    let mut targets = Vec::new();
    for qos in 0..=2 {
        let mut mqtt = Mqtt::new(server.address(), &format!("s3/events/{qos}"), qos).unwrap();
        mqtt.user = Some("teifs".into());
        mqtt.password = Some(Zeroizing::new("pw".into()));
        targets.push(TargetConfig::new(&format!("q{qos}"), TargetKind::Mqtt(mqtt)).unwrap());
    }
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(&dir.path().join("events.db"), targets).unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    for qos in 0..=2 {
        let arn = TargetArn::parse(&format!("arn:teifs:sqs::q{qos}:mqtt")).unwrap();
        notifier.send_now(&arn, b"test".to_vec()).await.unwrap();
        notifier
            .queue(vec![(arn.clone(), put.clone()), (arn, put.clone())])
            .await
            .unwrap();
    }
    let mut published = server.published(6).await;
    assert_eq!(published.len(), 6, "the tests publish nothing");
    published.sort_by_key(|m| m.qos);
    for (i, message) in published.iter().enumerate() {
        let qos = u8::try_from(i / 2).unwrap();
        assert_eq!(message.qos, qos);
        assert_eq!(message.topic, format!("s3/events/{qos}"));
        assert_eq!(message.body.as_bytes(), put);
    }
    let connects = server.connects();
    assert!(connects.iter().all(|c| c.clean
        && c.keep_alive == crate::mqtt::KEEP_ALIVE
        && c.user.as_deref() == Some("teifs")
        && c.client_id.starts_with("teifs")));
    notifier.stop().await;

    // A publish the broker doesn't take fails, whatever its quality of service.
    server.deny("s3/denied");
    for qos in 0..=2 {
        let mut denied = Mqtt::new(server.address(), "s3/denied", qos).unwrap();
        denied.user = Some("teifs".into());
        denied.password = Some(Zeroizing::new("pw".into()));
        denied.test().await.unwrap();
        assert!(denied.send(b"{}").await.is_err(), "QoS {qos}");
    }

    let mut wrong = Mqtt::new(server.address(), "t", 1).unwrap();
    wrong.user = Some("teifs".into());
    wrong.password = Some(Zeroizing::new("nope".into()));
    assert!(
        wrong
            .test()
            .await
            .unwrap_err()
            .contains("refused the user or password")
    );

    let (address, ca_pem) = tls_in_front_of(server.address()).await;
    let mut secure = Mqtt::new(&address, "s3/tls", 1).unwrap();
    secure.user = Some("teifs".into());
    secure.password = Some(Zeroizing::new("pw".into()));
    secure.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert!(secure.shown().starts_with("mqtts://"));
    secure.send(b"{}").await.unwrap();
    assert!(
        server
            .published(7)
            .await
            .iter()
            .any(|m| m.topic == "s3/tls")
    );
}

#[tokio::test]
async fn sqs_is_sent_each_event_as_s3_sends_it() {
    use crate::testing::AwsServer;
    let server = AwsServer::start("eu-west-1", "AKIDTEIFS", "s3cret").await;
    let keys = || AwsCredentials {
        access_key: "AKIDTEIFS".into(),
        secret: Zeroizing::new("s3cret".into()),
        session_token: None,
    };
    let standard_url = format!("{}/123456789012/events", server.url());
    let fifo_url = format!("{}/123456789012/events.fifo", server.url());
    let mut targets = Vec::new();
    for (id, url) in [("std", &standard_url), ("fifo", &fifo_url)] {
        let mut sqs = Sqs::new(url, Some("eu-west-1")).unwrap();
        sqs.credentials = Some(keys());
        targets.push(TargetConfig::new(id, TargetKind::Sqs(sqs)).unwrap());
    }
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(&dir.path().join("events.db"), targets).unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    let test = br#"{"Service":"Amazon S3","Event":"s3:TestEvent","Bucket":"photos"}"#;
    for id in ["std", "fifo"] {
        let arn = TargetArn::parse(&format!("arn:teifs:sqs::{id}:sqs")).unwrap();
        notifier.send_now(&arn, test.to_vec()).await.unwrap();
        notifier.queue(vec![(arn, put.clone())]).await.unwrap();
    }
    let requests = server.requests(4).await;
    notifier.stop().await;
    let records = serde_json::from_slice::<serde_json::Value>(&put).unwrap()["Records"].clone();
    for request in &requests {
        assert_eq!(request.target, "AmazonSQS.SendMessage");
        assert_eq!(request.path, "/");
        let sent: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        let body = sent["MessageBody"].as_str().unwrap();
        let fifo = sent["QueueUrl"] == fifo_url.as_str();
        if body.contains("s3:TestEvent") {
            assert_eq!(body.as_bytes(), test, "the test event is sent as it is");
            assert_eq!(fifo, sent["MessageGroupId"] == "teifs-test");
        } else {
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(
                body,
                serde_json::json!({ "Records": records }),
                "no envelope"
            );
            assert_eq!(fifo, sent["MessageGroupId"] == "photos/a.jpg");
        }
        assert_eq!(
            fifo,
            sent["MessageDeduplicationId"].as_str().map(str::len) == Some(64)
        );
    }

    // AWS's errors are named, and an answer for another message is caught.
    let mut sqs = Sqs::new(&standard_url, Some("eu-west-1")).unwrap();
    sqs.credentials = Some(keys());
    let client = reqwest::Client::new();
    server.wrong_digest(true);
    assert!(
        sqs.send(&client, b"{}")
            .await
            .unwrap_err()
            .contains("doesn't match")
    );
    server.wrong_digest(false);
    server.missing(&standard_url);
    let missing = sqs.send(&client, b"{}").await.unwrap_err();
    assert!(missing.contains("QueueDoesNotExist"), "{missing}");
    let mut elsewhere = Sqs::new(&fifo_url, Some("us-east-1")).unwrap();
    elsewhere.credentials = Some(keys());
    let refused = elsewhere.send(&client, b"{}").await.unwrap_err();
    assert!(refused.contains("InvalidSignatureException"), "{refused}");
    let unsigned = Sqs::new(&fifo_url, Some("eu-west-1")).unwrap();
    assert!(unsigned.send(&client, b"{}").await.is_err());
    let mut temporary = Sqs::new(&fifo_url, Some("eu-west-1")).unwrap();
    temporary.credentials = Some(AwsCredentials {
        session_token: Some(Zeroizing::new("session".into())),
        ..keys()
    });
    temporary.send(&client, b"{}").await.unwrap();
}
