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
        "arn:aws:sqs:eu-west-2:123456789012:orders",
        "arn:aws:sqs:eu-west-1:210987654321:orders",
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
    use crate::testing::{NsqServer, NsqSetup};
    let server = NsqServer::start(NsqSetup::default()).await;
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

/// NSQ over TLS, as `nsqd` negotiates it after `IDENTIFY`, and `AUTH` over it: the
/// `nsqd` is verified with the operator's CA; one without TLS, or one the CA didn't sign,
/// is refused; the secret is sent only over TLS, and an `nsqd` that doesn't negotiate is
/// spoken to as before.
#[tokio::test]
async fn nsq_is_reached_over_tls_with_auth() {
    use crate::testing::{NsqServer, NsqSetup};
    let (acceptor, ca_pem) = test_tls();
    let server = NsqServer::start(NsqSetup {
        tls: Some(acceptor.clone()),
        secret: Some("s3cret".into()),
        ..NsqSetup::default()
    })
    .await;
    let secure = |address: &str, secret: Option<&str>| {
        let mut nsq = Nsq::new(address, "s3-events").unwrap();
        nsq.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
        nsq.secret = secret.map(|s| Zeroizing::new(s.to_owned()));
        nsq
    };
    let nsq = secure(server.address(), Some("s3cret"));
    assert_eq!(
        nsq.shown(),
        format!("nsq://{} topic s3-events (TLS)", server.address())
    );
    nsq.send(&message("s3:ObjectCreated:Put", "b/k"))
        .await
        .unwrap();
    assert_eq!(server.published(1).await.len(), 1);
    let connection = &server.connections()[0];
    assert!(connection.tls);
    assert_eq!(connection.identify["tls_v1"], true);
    assert_eq!(connection.identify["feature_negotiation"], true);
    assert_eq!(connection.auths, ["s3cret"]);

    let err = secure(server.address(), Some("wrong"))
        .test()
        .await
        .unwrap_err();
    assert!(err.contains("E_UNAUTHORIZED"), "{err}");
    let err = secure(server.address(), None).test().await.unwrap_err();
    assert!(err.contains("TEIFS_NOTIFY_NSQ_SECRET_ID"), "{err}");
    let mut plain = secure(server.address(), Some("s3cret"));
    plain.tls = None;
    let err = plain.test().await.unwrap_err();
    assert!(err.contains("only over TLS"), "{err}");
    assert!(
        server
            .connections()
            .iter()
            .all(|c| c.tls || c.auths.is_empty())
    );
    let mut untrusted = secure(server.address(), Some("s3cret"));
    untrusted.tls = Some(tls_config(None, None).unwrap());
    assert!(untrusted.test().await.unwrap_err().contains("TLS failed"));

    for setup in [
        NsqSetup::default(),
        NsqSetup {
            negotiates: false,
            ..NsqSetup::default()
        },
    ] {
        let without = NsqServer::start(setup).await;
        let err = secure(without.address(), None).test().await.unwrap_err();
        assert!(err.contains("doesn't take TLS"), "{err}");
    }
    let old = NsqServer::start(NsqSetup {
        negotiates: false,
        ..NsqSetup::default()
    })
    .await;
    let nsq = Nsq::new(old.address(), "t").unwrap();
    nsq.send(&message("s3:ObjectCreated:Put", "b/k"))
        .await
        .unwrap();
    assert_eq!(old.published(1).await.len(), 1);
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

/// MQTT over a WebSocket: the upgrade asks for `mqtt` at the URL's path, every frame sent
/// is masked, frames split in pieces are put back together and pings are answered; over
/// TLS too.
#[tokio::test]
async fn mqtt_publishes_over_websockets() {
    use crate::testing::MqttServer;
    let server = MqttServer::over_websocket(Some(("teifs", "pw"))).await;
    let signed_in = |address: &str, qos| {
        let mut mqtt = Mqtt::new(address, "s3/events", qos).unwrap();
        mqtt.user = Some("teifs".into());
        mqtt.password = Some(Zeroizing::new("pw".into()));
        mqtt
    };
    for qos in 0..=2 {
        let mqtt = signed_in(&format!("ws://{}/mqtt", server.address()), qos);
        mqtt.test().await.unwrap();
        mqtt.send(b"{\"n\":1}").await.unwrap();
        mqtt.send(&vec![b'x'; 70_000]).await.unwrap();
    }
    let published = server.published(6).await;
    assert_eq!(
        published.iter().map(|m| m.qos).collect::<Vec<_>>(),
        [0, 0, 1, 1, 2, 2]
    );
    assert_eq!(published[0].body, "{\"n\":1}");
    assert_eq!(published[1].body.len(), 70_000);
    let upgrades = server.upgrades();
    assert_eq!(upgrades.len(), 3, "one connection for each target, kept");
    for upgrade in &upgrades {
        assert_eq!(
            (
                upgrade.path.as_str(),
                upgrade.host.as_str(),
                upgrade.protocol.as_str()
            ),
            ("/mqtt", server.address(), "mqtt")
        );
        assert!(upgrade.masked);
    }
    assert!(upgrades.iter().all(|u| u.pongs > 0), "{upgrades:?}");

    let mut wrong = signed_in(&format!("ws://{}", server.address()), 1);
    wrong.password = Some(Zeroizing::new("nope".into()));
    assert!(
        wrong
            .test()
            .await
            .unwrap_err()
            .contains("refused the user or password")
    );
    assert_eq!(server.upgrades().last().unwrap().path, "/");

    // A broker that isn't a WebSocket's.
    let plain = MqttServer::start(None).await;
    let err = signed_in(&format!("ws://{}/mqtt", plain.address()), 1)
        .test()
        .await
        .unwrap_err();
    assert!(err.contains("WebSocket upgrade"), "{err}");

    let (address, ca_pem) = tls_in_front_of(server.address()).await;
    let mut secure = signed_in(&format!("wss://{address}/mqtt"), 1);
    assert!(secure.test().await.is_err(), "not the system's CA");
    secure.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert!(secure.shown().starts_with("wss://"));
    secure.send(b"{}").await.unwrap();
    assert_eq!(server.published(7).await[6].body, "{}");
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

#[tokio::test]
async fn sns_is_published_each_event_as_s3_publishes_it() {
    use crate::testing::AwsServer;
    let server = AwsServer::start("eu-west-1", "AKIDTEIFS", "s3cret").await;
    let keys = || AwsCredentials {
        access_key: "AKIDTEIFS".into(),
        secret: Zeroizing::new("s3cret".into()),
        session_token: None,
    };
    let topic = |name: &str| {
        let mut sns = Sns::new(
            &format!("arn:aws:sns:eu-west-1:123456789012:{name}"),
            Some(server.url()),
        )
        .unwrap();
        sns.credentials = Some(keys());
        sns
    };
    let targets = vec![
        TargetConfig::new("std", TargetKind::Sns(topic("events"))).unwrap(),
        TargetConfig::new("fifo", TargetKind::Sns(topic("events.fifo"))).unwrap(),
    ];
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(&dir.path().join("events.db"), targets).unwrap();
    assert_eq!(
        notifier
            .resolve("arn:aws:sns:eu-west-1:123456789012:events.fifo")
            .map(|t| t.to_string())
            .as_deref(),
        Some("arn:teifs:sqs::fifo:sns")
    );
    let put = message("s3:ObjectCreated:Put", "photos/a b.jpg");
    let test = br#"{"Service":"Amazon S3","Event":"s3:TestEvent","Bucket":"photos"}"#;
    for id in ["std", "fifo"] {
        let arn = TargetArn::parse(&format!("arn:teifs:sqs::{id}:sns")).unwrap();
        notifier.send_now(&arn, test.to_vec()).await.unwrap();
        notifier.queue(vec![(arn, put.clone())]).await.unwrap();
    }
    let requests = server.requests(4).await;
    notifier.stop().await;
    let records = serde_json::from_slice::<serde_json::Value>(&put).unwrap()["Records"].clone();
    for request in &requests {
        assert_eq!(request.target, "AmazonSNS.Publish");
        let form: std::collections::BTreeMap<String, String> =
            form_urlencoded::parse(request.body.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(form["Version"], "2010-03-31");
        assert_eq!(form["Subject"], "Amazon S3 Notification");
        let fifo = form["TopicArn"].strip_suffix(".fifo").is_some();
        let message = &form["Message"];
        if message.contains("s3:TestEvent") {
            assert_eq!(message.as_bytes(), test);
        } else {
            let body: serde_json::Value = serde_json::from_str(message).unwrap();
            assert_eq!(body, serde_json::json!({ "Records": records }));
            if fifo {
                // A key SNS won't take as a group is grouped by its digest.
                assert_eq!(form["MessageGroupId"].len(), 64);
            }
        }
        assert_eq!(fifo, form.contains_key("MessageDeduplicationId"));
    }

    let client = reqwest::Client::new();
    let gone = topic("gone");
    server.missing(&gone.topic_arn);
    let missing = gone.send(&client, b"{}").await.unwrap_err();
    assert!(
        missing.contains("NotFound (Topic does not exist)"),
        "{missing}"
    );
    server.wrong_digest(true);
    let odd = topic("events").send(&client, b"{}").await.unwrap_err();
    assert!(odd.contains("no message id"), "{odd}");
    server.wrong_digest(false);
    let mut elsewhere = topic("events");
    elsewhere.region = "us-east-1".into();
    let refused = elsewhere.send(&client, b"{}").await.unwrap_err();
    assert!(refused.contains("SignatureDoesNotMatch"), "{refused}");
}

#[tokio::test]
async fn lambda_is_invoked_with_each_event_as_s3_invokes_it() {
    use crate::testing::AwsServer;
    let server = AwsServer::start("eu-west-1", "AKIDTEIFS", "s3cret").await;
    let function = |name: &str| {
        let mut lambda = Lambda::new(
            &format!("arn:aws:lambda:eu-west-1:123456789012:function:{name}"),
            Some(server.url()),
        )
        .unwrap();
        lambda.credentials = Some(AwsCredentials {
            access_key: "AKIDTEIFS".into(),
            secret: Zeroizing::new("s3cret".into()),
            session_token: None,
        });
        lambda
    };
    let target = TargetConfig::new("thumbs", TargetKind::Lambda(function("thumbs:live"))).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(&dir.path().join("events.db"), vec![target]).unwrap();
    let arn = notifier
        .resolve("arn:aws:lambda:eu-west-1:123456789012:function:thumbs:live")
        .unwrap();
    assert_eq!(arn.to_string(), "arn:teifs:sqs::thumbs:lambda");
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    notifier.send_now(&arn, b"test".to_vec()).await.unwrap();
    notifier.queue(vec![(arn, put.clone())]).await.unwrap();
    let requests = server.requests(2).await;
    notifier.stop().await;
    assert_eq!(requests[0].target, "Lambda.Invoke:DryRun", "no test event");
    assert_eq!(requests[1].target, "Lambda.Invoke:Event");
    assert_eq!(
        requests[1].path,
        "/2015-03-31/functions/arn%3Aaws%3Alambda%3Aeu-west-1%3A123456789012%3Afunction%3Athumbs%3Alive/invocations"
    );
    let records = serde_json::from_slice::<serde_json::Value>(&put).unwrap()["Records"].clone();
    let sent: serde_json::Value = serde_json::from_str(&requests[1].message).unwrap();
    assert_eq!(sent, serde_json::json!({ "Records": records }));

    let client = reqwest::Client::new();
    let gone = function("gone");
    server.missing(&gone.function_arn);
    let missing = gone.test(&client).await.unwrap_err();
    assert!(
        missing.contains("404 Not Found: ResourceNotFoundException (Function not found"),
        "{missing}"
    );
    assert!(gone.send(&client, &put).await.is_err());
    server.wrong_digest(true);
    assert!(
        function("f").send(&client, &put).await.is_err(),
        "a 200 isn't a 202"
    );
    server.wrong_digest(false);
    let mut elsewhere = function("f");
    elsewhere.region = "us-east-1".into();
    let refused = elsewhere.test(&client).await.unwrap_err();
    assert!(refused.contains("InvalidSignatureException"), "{refused}");
    function("f:$LATEST").test(&client).await.unwrap();
}

#[tokio::test]
async fn event_bridge_names_what_it_refuses() {
    use crate::testing::AwsServer;
    let server = AwsServer::start("eu-west-1", "AKIDTEIFS", "s3cret").await;
    let bus = |name: &str| {
        let mut bus = EventBridge::new(
            &format!("arn:aws:events:eu-west-1:123456789012:event-bus/{name}"),
            Some(server.url()),
            None,
        )
        .unwrap();
        bus.credentials = Some(AwsCredentials {
            access_key: "AKIDTEIFS".into(),
            secret: Zeroizing::new("s3cret".into()),
            session_token: None,
        });
        bus
    };
    let client = reqwest::Client::new();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    bus("default").send(&client, &put).await.unwrap();
    let sent = server.requests(1).await;
    assert_eq!(sent[0].target, "AWSEvents.PutEvents");
    // An event S3 doesn't send there isn't sent.
    let read = message("s3:ObjectAccessed:Get", "photos/a.jpg");
    bus("default").send(&client, &read).await.unwrap();
    let gone = bus("gone");
    server.missing(&gone.bus_arn);
    let missing = gone.send(&client, &put).await.unwrap_err();
    assert!(missing.contains("ResourceNotFoundException"), "{missing}");
    server.wrong_digest(true);
    let failed = bus("default").send(&client, &put).await.unwrap_err();
    assert!(failed.contains("InternalFailure"), "{failed}");
    server.wrong_digest(false);
    let mut elsewhere = bus("default");
    elsewhere.region = "us-east-1".into();
    let refused = elsewhere.send(&client, &put).await.unwrap_err();
    assert!(refused.contains("InvalidSignatureException"), "{refused}");
    // The put, the missing bus and the failed entry: nothing for the read, and the
    // refused request isn't taken.
    assert_eq!(server.requests(0).await.len(), 3);
}

fn kafka_target(id: &str, kafka: Kafka) -> (TargetArn, TargetConfig) {
    let config = TargetConfig::new(id, TargetKind::Kafka(kafka)).unwrap();
    (config.arn(), config)
}

/// Kafka targets: the topic's leaders are looked up on any bootstrap broker, and each
/// event is produced, keyed by its object, to the partition Kafka's own clients pick for
/// the key, on that partition's leader, in order.
#[tokio::test]
async fn kafka_produces_each_event_to_its_objects_partition_leader() {
    use crate::testing::{KafkaServer, KafkaSetup};
    let cluster = KafkaServer::start(KafkaSetup::new(3, "s3-events", 6)).await;
    // Only the last broker is named, and the first doesn't answer.
    let brokers = format!("127.0.0.1:1;{}", cluster.addresses()[2]);
    let (arn, config) = kafka_target("stream", Kafka::new(&brokers, "s3-events").unwrap());
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(&dir.path().join("events.db"), vec![config]).unwrap();
    notifier.send_now(&arn, b"test".to_vec()).await.unwrap();
    let events: Vec<Vec<u8>> = [
        ("s3:ObjectCreated:Put", "photos/a.jpg"),
        ("s3:ObjectCreated:Put", "photos/b.jpg"),
        ("s3:ObjectRemoved:Delete", "photos/a.jpg"),
        ("s3:ObjectCreated:Copy", "docs/c.txt"),
    ]
    .iter()
    .map(|(name, key)| message(name, key))
    .collect();
    notifier
        .queue(events.iter().map(|e| (arn.clone(), e.clone())).collect())
        .await
        .unwrap();
    let records = cluster.records(4).await;
    assert_eq!(records.len(), 4, "the test produces nothing");
    for (record, event) in records.iter().zip(&events) {
        let key = serde_json::from_slice::<serde_json::Value>(event).unwrap()["Key"]
            .as_str()
            .unwrap()
            .to_owned();
        let partition = crate::kafka::wire::partition(key.as_bytes(), 6);
        assert_eq!(record.key.as_deref(), Some(key.as_str()));
        assert_eq!(record.value.as_bytes(), event);
        assert_eq!(record.partition, partition, "{key}");
        assert_eq!(record.broker, partition % 3, "its leader took it");
        assert_eq!((record.acks, record.compression), (-1, 0));
    }
    assert_eq!(
        cluster.lookups(),
        1,
        "the test's connection was kept for the events"
    );
    notifier.stop().await;

    let missing = Kafka::new(&cluster.addresses()[0], "missing").unwrap();
    let err = missing.test().await.unwrap_err();
    assert!(err.contains("`missing` doesn't exist"), "{err}");
    let down = Kafka::new("127.0.0.1:1;127.0.0.1:2", "s3-events").unwrap();
    let err = down.test().await.unwrap_err();
    assert!(
        err.starts_with("no broker took the connection (127.0.0.1:1: "),
        "{err}"
    );
}

/// A leader that moved is looked up again at once; a topic whose leader is being elected
/// is waited for, a little; a record the leader refuses fails with the leader's reason;
/// `acks=1` and gzip are as asked.
#[tokio::test]
async fn kafka_follows_leaders_and_names_refusals() {
    use crate::testing::{KafkaServer, KafkaSetup};
    let cluster = KafkaServer::start(KafkaSetup::new(2, "t", 1)).await;
    let kafka = Kafka::new(&cluster.addresses()[0], "t").unwrap();
    let put = message("s3:ObjectCreated:Put", "b/k");
    kafka.send(&put).await.unwrap();
    cluster.move_leader(0, 1);
    kafka.send(&put).await.unwrap();
    let records = cluster.records(2).await;
    assert_eq!((records[0].broker, records[1].broker), (0, 1));
    assert_eq!(
        cluster.lookups(),
        2,
        "looked up again once, on the same connection"
    );

    cluster.refuse(19, 1);
    let err = kafka.send(&put).await.unwrap_err();
    assert_eq!(err, "it answered NOT_ENOUGH_REPLICAS (19)");
    kafka.send(&put).await.unwrap();
    assert_eq!(cluster.records(3).await.len(), 3);
    assert_eq!(cluster.lookups(), 2, "a refusal keeps the connection");

    cluster.electing(2);
    kafka.test().await.unwrap();
    cluster.electing(3);
    let err = kafka.test().await.unwrap_err();
    assert!(err.contains("LEADER_NOT_AVAILABLE"), "{err}");

    let mut quick = Kafka::new(&cluster.addresses()[1], "t").unwrap();
    quick.acks = Acks::Leader;
    quick.compression = Compression::Gzip;
    quick.send(&put).await.unwrap();
    let last = cluster.records(4).await.pop().unwrap();
    assert_eq!((last.acks, last.compression), (1, 1));
    assert_eq!(last.value.as_bytes(), put);
}

/// SASL: PLAIN and SCRAM sign in, a wrong password or mechanism is named, and a broker
/// older than the versions used is refused.
#[tokio::test]
async fn kafka_signs_in_with_sasl() {
    use crate::testing::{KafkaServer, KafkaSetup};
    for mechanism in ["plain", "scram-sha-256", "scram-sha-512"] {
        let mechanism = SaslMechanism::parse(mechanism).unwrap();
        let mut setup = KafkaSetup::new(2, "t", 2);
        setup.sasl = Some((mechanism.name().into(), "teifs".into(), "s3cr=t,pw".into()));
        let cluster = KafkaServer::start(setup).await;
        let signed = |password: &str, mechanism| {
            let mut kafka = Kafka::new(&cluster.addresses()[0], "t").unwrap();
            kafka.sasl = Some(KafkaSasl {
                mechanism,
                user: "teifs".into(),
                password: Zeroizing::new(password.into()),
            });
            kafka
        };
        let kafka = signed("s3cr=t,pw", mechanism);
        for key in ["b/one", "b/two", "b/three"] {
            kafka
                .send(&message("s3:ObjectCreated:Put", key))
                .await
                .unwrap();
        }
        assert_eq!(cluster.records(3).await.len(), 3);
        let signins = cluster.signins();
        assert!(
            signins.len() >= 2,
            "each broker's connection signs in: {signins:?}"
        );
        assert!(
            signins
                .iter()
                .all(|s| *s == format!("{} teifs", mechanism.name()))
        );

        let err = signed("wrong", mechanism).test().await.unwrap_err();
        assert!(err.contains("refused the user or password"), "{err}");
        let other = if mechanism == SaslMechanism::Plain {
            SaslMechanism::Scram(ScramHash::Sha256)
        } else {
            SaslMechanism::Plain
        };
        let err = signed("s3cr=t,pw", other).test().await.unwrap_err();
        assert_eq!(
            err,
            format!(
                "it doesn't take SASL {}, only {}",
                other.name(),
                mechanism.name()
            )
        );
        let err = Kafka::new(&cluster.addresses()[0], "t")
            .unwrap()
            .send(b"{}")
            .await
            .unwrap_err();
        assert!(err.contains("connection failed"), "unsigned: {err}");
    }

    // A server that doesn't know the password can't prove it does.
    let mut impostor = KafkaSetup::new(1, "t", 1);
    impostor.sasl = Some(("SCRAM-SHA-256".into(), "teifs".into(), "pw".into()));
    impostor.impostor = true;
    let cluster = KafkaServer::start(impostor).await;
    let mut kafka = Kafka::new(&cluster.addresses()[0], "t").unwrap();
    kafka.sasl = Some(KafkaSasl {
        mechanism: SaslMechanism::Scram(ScramHash::Sha256),
        user: "teifs".into(),
        password: Zeroizing::new("pw".into()),
    });
    let err = kafka.test().await.unwrap_err();
    assert!(err.contains("it isn't the server"), "{err}");

    // Brokers older than the versions used: Produce v3, or SASL's handshake v1.
    for (api, newest) in [(0, 2), (17, 0)] {
        let mut old = KafkaSetup::new(1, "t", 1);
        old.sasl = Some(("PLAIN".into(), "teifs".into(), "pw".into()));
        for version in &mut old.versions {
            if version.0 == api {
                version.2 = newest;
            }
        }
        let cluster = KafkaServer::start(old).await;
        let mut kafka = Kafka::new(&cluster.addresses()[0], "t").unwrap();
        kafka.sasl = Some(KafkaSasl {
            mechanism: SaslMechanism::Plain,
            user: "teifs".into(),
            password: Zeroizing::new("pw".into()),
        });
        let err = kafka.test().await.unwrap_err();
        assert!(err.contains(&format!("API {api} version")), "{err}");
        assert!(err.contains("use Kafka 1.0 or later"), "{err}");
    }
}

/// Kafka over TLS: each broker verified with the operator's CA, leaders included.
#[tokio::test]
async fn kafka_is_reached_over_tls() {
    use crate::testing::{KafkaServer, KafkaSetup};
    let cluster = KafkaServer::start(KafkaSetup::new(2, "t", 2)).await;
    let mut ca = String::new();
    for broker in 0..2 {
        let (address, ca_pem) = tls_in_front_of(&cluster.addresses()[broker]).await;
        let (host, port) = address.rsplit_once(':').unwrap();
        cluster.advertise(broker, host, port.parse().unwrap());
        ca.push_str(&ca_pem);
    }
    // The bootstrap broker is reached through a proxy of its own.
    let (bootstrap, ca_pem) = tls_in_front_of(&cluster.addresses()[0]).await;
    ca.push_str(&ca_pem);
    let mut kafka = Kafka::new(&bootstrap, "t").unwrap();
    kafka.tls = Some(tls_config(Some(ca.as_bytes()), None).unwrap());
    assert!(kafka.shown().starts_with("kafka+tls://"));
    for key in ["b/one", "b/two", "b/three", "b/four"] {
        kafka
            .send(&message("s3:ObjectCreated:Put", key))
            .await
            .unwrap();
    }
    let records = cluster.records(4).await;
    assert!(records.iter().any(|r| r.broker == 0) && records.iter().any(|r| r.broker == 1));

    kafka.tls = Some(tls_config(None, None).unwrap());
    let err = kafka.test().await.unwrap_err();
    assert!(err.contains("TLS failed"), "{err}");
}

fn amqp_target(address: &str, vhost: &str, exchange: &str, key: &str) -> Amqp {
    let mut amqp = Amqp::new(&format!("amqp://{address}/{vhost}"), exchange, key).unwrap();
    amqp.user = Some("teifs".into());
    amqp.password = Some(Zeroizing::new("pw".into()));
    amqp
}

fn amqp_setup() -> crate::testing::AmqpSetup {
    crate::testing::AmqpSetup {
        login: ("teifs".into(), "pw".into()),
        vhosts: vec!["/".into(), "prod".into()],
        ..crate::testing::AmqpSetup::default()
    }
}

/// AMQP targets: the exchange is declared when the connection is made, and each event is
/// published to it as JSON with `MinIO`'s headers, persistent, each confirmed by the
/// broker; a body larger than a frame is split as the broker agreed.
#[tokio::test]
async fn amqp_publishes_each_event_with_a_confirm() {
    use crate::testing::AmqpServer;
    let broker = AmqpServer::start(amqp_setup()).await;
    broker.bind("s3", "events");
    let amqp = amqp_target(broker.address(), "prod", "s3", "events");
    let config = TargetConfig::new("rabbit", TargetKind::Amqp(amqp.clone())).unwrap();
    let arn = config.arn();
    assert_eq!(arn.to_string(), "arn:teifs:sqs::rabbit:amqp");
    let dir = tempfile::tempdir().unwrap();
    let notifier = Notifier::start(&dir.path().join("events.db"), vec![config]).unwrap();
    notifier.send_now(&arn, b"test".to_vec()).await.unwrap();
    let put = message("s3:ObjectCreated:Put", "photos/a.jpg");
    let delete = message("s3:ObjectRemoved:Delete", "photos/a.jpg");
    notifier
        .queue(vec![(arn.clone(), put.clone()), (arn, delete.clone())])
        .await
        .unwrap();
    let messages = broker.messages(2).await;
    assert_eq!(messages.len(), 2, "the test publishes nothing");
    for (message, (body, name)) in messages.iter().zip([
        (&put, "s3:ObjectCreated:Put"),
        (&delete, "s3:ObjectRemoved:Delete"),
    ]) {
        assert_eq!(message.body.as_bytes(), body);
        assert_eq!(
            (
                message.vhost.as_str(),
                message.exchange.as_str(),
                message.routing_key.as_str()
            ),
            ("prod", "s3", "events")
        );
        assert_eq!(message.content_type, "application/json");
        assert_eq!(
            message.headers,
            [
                ("minio-bucket".to_owned(), "photos".to_owned()),
                ("minio-event".to_owned(), name.to_owned())
            ]
        );
        assert_eq!((message.delivery_mode, message.mandatory), (2, false));
    }
    let declares = broker.declares();
    assert!(!declares.is_empty());
    assert!(
        declares.iter().all(|d| d.name == "s3"
            && !d.passive
            && d.exchange == crate::amqp::Exchange::default())
    );
    assert!(broker.heartbeats().iter().all(|h| *h == 0), "no heartbeats");
    notifier.stop().await;

    // Larger than a frame: split into as many as it takes.
    let large = vec![b'x'; 10_000];
    amqp.send(&large).await.unwrap();
    let last = broker.messages(3).await.pop().unwrap();
    assert_eq!((last.body.len(), last.frames), (10_000, 3));
    assert_eq!(
        last.headers[0],
        ("minio-bucket".to_owned(), String::new()),
        "not an event"
    );
}

/// What the broker refuses is named: the user, the virtual host, an exchange declared
/// with other settings or missing, a message it nacks or no queue takes.
#[tokio::test]
async fn amqp_names_what_the_broker_refuses() {
    use crate::testing::{AmqpServer, AmqpSetup};
    let mut setup = amqp_setup();
    setup
        .exchanges
        .insert("logs".into(), ("fanout".into(), false));
    let broker = AmqpServer::start(setup).await;
    let address = broker.address().to_owned();

    let mut wrong = amqp_target(&address, "", "logs", "k");
    wrong.password = Some(Zeroizing::new("nope".into()));
    let err = wrong.test().await.unwrap_err();
    assert!(err.contains("403 ACCESS_REFUSED"), "{err}");
    let err = amqp_target(&address, "staging", "logs", "k")
        .test()
        .await
        .unwrap_err();
    assert!(err.contains("530 NOT_ALLOWED"), "{err}");

    let mut logs = amqp_target(&address, "", "logs", "k");
    let err = logs.test().await.unwrap_err();
    assert!(
        err.contains("406 PRECONDITION_FAILED") && err.contains("declare=false"),
        "{err}"
    );
    logs.declare = None;
    logs.test().await.unwrap();
    assert!(broker.declares().last().unwrap().passive);
    let mut fanout = crate::amqp::Exchange::default();
    fanout.set_kind("fanout").unwrap();
    fanout.durable = false;
    logs.declare = Some(fanout);
    logs.test().await.unwrap();
    let mut missing = amqp_target(&address, "", "missing", "k");
    missing.declare = None;
    let err = missing.test().await.unwrap_err();
    assert!(err.contains("404 NOT_FOUND"), "{err}");

    let body = message("s3:ObjectCreated:Put", "b/k");
    logs.send(&body).await.unwrap();
    broker.nack(1);
    let err = logs.send(&body).await.unwrap_err();
    assert!(err.contains("nack"), "{err}");

    logs.mandatory = true;
    let err = logs.send(&body).await.unwrap_err();
    assert!(
        err.contains("no queue took it") && err.contains("312 NO_ROUTE"),
        "{err}"
    );
    broker.bind("logs", "k");
    logs.send(&body).await.unwrap();
    logs.persistent = false;
    logs.send(&body).await.unwrap();
    let messages = broker.messages(3).await;
    assert_eq!(messages.len(), 3, "the returned one isn't kept");
    assert_eq!(
        messages
            .iter()
            .map(|m| (m.mandatory, m.delivery_mode))
            .collect::<Vec<_>>(),
        [(false, 2), (true, 2), (true, 1)]
    );

    // The default exchange: the routing key names the queue, and nothing is declared.
    let declared = broker.declares().len();
    let queue = amqp_target(&address, "", "", "q1");
    queue.send(&body).await.unwrap();
    assert_eq!(broker.declares().len(), declared);
    assert_eq!(broker.messages(4).await[3].exchange, "");

    // The guest login, when no user is given.
    let guest = AmqpServer::start(AmqpSetup::default()).await;
    let mut anonymous = Amqp::new(&format!("amqp://{}", guest.address()), "s3", "k").unwrap();
    anonymous.test().await.unwrap();
    anonymous.user = Some("teifs".into());
    assert!(anonymous.test().await.is_err());
}

/// AMQP over TLS, `amqps://`: the broker verified with the operator's CA.
#[tokio::test]
async fn amqp_is_reached_over_tls() {
    use crate::testing::AmqpServer;
    let broker = AmqpServer::start(amqp_setup()).await;
    let (address, ca_pem) = tls_in_front_of(broker.address()).await;
    let mut amqp = Amqp::new(&format!("amqps://{address}"), "s3", "k").unwrap();
    assert!(amqp.wants_tls());
    amqp.user = Some("teifs".into());
    amqp.password = Some(Zeroizing::new("pw".into()));
    amqp.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert!(amqp.shown().starts_with("amqps://"));
    amqp.send(&message("s3:ObjectCreated:Put", "b/k"))
        .await
        .unwrap();
    assert_eq!(broker.messages(1).await.len(), 1);
    amqp.tls = Some(tls_config(None, None).unwrap());
    let err = amqp.test().await.unwrap_err();
    assert!(err.contains("TLS failed"), "{err}");
}

fn postgres(server: &crate::testing::PostgresServer, format: Format) -> Postgres {
    let mut pg = Postgres::new(server.address(), "s3", "events", format, "teifs").unwrap();
    pg.password = Some(Zeroizing::new("pw".into()));
    pg
}

/// PostgreSQL targets in the `namespace` format: the table is made when the connection
/// is, with `MinIO`'s columns; each event sets its object's row, bound as parameters (a
/// key with a quote is only a value), and a removal deletes it.
#[tokio::test]
async fn postgres_keeps_a_row_per_object() {
    use crate::testing::{PostgresServer, PostgresSetup};
    let server = PostgresServer::start(PostgresSetup::default()).await;
    let pg = postgres(&server, Format::Namespace);
    pg.test().await.unwrap();
    let (columns, rows) = server.table("events").unwrap();
    assert_eq!(columns, "(key VARCHAR PRIMARY KEY, value JSONB)");
    assert!(rows.is_empty());
    for (name, key) in [
        ("s3:ObjectCreated:Put", "b/it's"),
        ("s3:ObjectCreated:Put", "b/k"),
        ("s3:ObjectCreated:Copy", "b/it's"),
        ("s3:ObjectRemoved:Delete", "b/k"),
    ] {
        pg.send(&message(name, key)).await.unwrap();
    }
    let rows = server.rows("events", 1).await;
    assert_eq!(rows[0][0], "b/it's");
    let value: serde_json::Value = serde_json::from_str(&rows[0][1]).unwrap();
    assert_eq!(value["Records"][0]["eventName"], "ObjectCreated:Copy");
    assert_eq!(value.as_object().unwrap().len(), 1, "{value}");
    let statements = server.statements();
    assert!(statements.iter().all(|(sql, _)| !sql.contains("it's")));
    assert_eq!(
        statements.last().unwrap(),
        &(
            "DELETE FROM events WHERE key = $1;".to_owned(),
            vec!["b/k".to_owned()]
        )
    );
    // One connection for all of it, which says who it is.
    let startups = server.startups();
    assert_eq!(startups.len(), 1);
    let parameters = &startups[0].parameters;
    assert_eq!(parameters["user"], "teifs");
    assert_eq!(parameters["database"], "s3");
    assert_eq!(parameters["application_name"], "teifs");
    assert_eq!(parameters["client_encoding"], "UTF8");
    assert!(startups.iter().all(|s| s.signed_in && !s.tls));
}

/// PostgreSQL targets in the `access` format, signed in with MD5: a table that's there is
/// used as it is, and each event is a row of its time and itself.
#[tokio::test]
async fn postgres_adds_a_row_per_event() {
    use crate::testing::{PgAuth, PostgresServer, PostgresSetup};
    let server = PostgresServer::start(PostgresSetup {
        auth: PgAuth::Md5,
        tables: [("\"S3 Log\"".to_owned(), "(given)".to_owned())].into(),
        ..PostgresSetup::default()
    })
    .await;
    let mut pg = postgres(&server, Format::Access);
    pg.table = "\"S3 Log\"".into();
    for (name, key) in [
        ("s3:ObjectCreated:Put", "b/k"),
        ("s3:ObjectRemoved:Delete", "b/k"),
    ] {
        pg.send(&message(name, key)).await.unwrap();
    }
    let rows = server.rows("\"S3 Log\"", 2).await;
    assert_eq!(server.table("\"S3 Log\"").unwrap().0, "(given)");
    assert_eq!(rows[1][0], "2026-09-30T12:00:00.000Z");
    let event: serde_json::Value = serde_json::from_str(&rows[1][1]).unwrap();
    assert_eq!(event["EventName"], "s3:ObjectRemoved:Delete");
    assert!(
        !server
            .statements()
            .iter()
            .any(|(sql, _)| sql.starts_with("CREATE"))
    );
}

/// What a PostgreSQL server refuses is named: the password, the database, a server that
/// can't prove it knows the password, a password asked for in the clear without TLS, and
/// a statement (which keeps the connection); a connection the server closed is made again.
#[tokio::test]
async fn postgres_names_what_the_server_refuses() {
    use crate::testing::{PgAuth, PgImpostor, PostgresServer, PostgresSetup};
    let server = PostgresServer::start(PostgresSetup::default()).await;
    let mut pg = postgres(&server, Format::Namespace);
    pg.password = Some(Zeroizing::new("wrong".into()));
    let err = pg.test().await.unwrap_err();
    assert!(
        err.contains("refused the user or password") && err.contains("28P01"),
        "{err}"
    );
    pg.password = None;
    let err = pg.test().await.unwrap_err();
    assert!(err.contains("TEIFS_NOTIFY_POSTGRESQL_PASSWORD_ID"), "{err}");
    let mut pg = postgres(&server, Format::Namespace);
    pg.database = "other".into();
    let err = pg.test().await.unwrap_err();
    assert!(err.contains("3D000") && err.contains("\"other\""), "{err}");

    // A table it may not read isn't made again.
    server.refuse(1);
    let err = postgres(&server, Format::Namespace)
        .test()
        .await
        .unwrap_err();
    assert!(err.contains("42501"), "{err}");
    assert!(
        !server
            .statements()
            .iter()
            .any(|(sql, _)| sql.starts_with("CREATE"))
    );

    let pg = postgres(&server, Format::Namespace);
    pg.send(&message("s3:ObjectCreated:Put", "b/1"))
        .await
        .unwrap();
    let connections = server.startups().len();
    server.refuse(1);
    let err = pg
        .send(&message("s3:ObjectCreated:Put", "b/2"))
        .await
        .unwrap_err();
    assert!(
        err.contains("42501") && err.contains("permission denied"),
        "{err}"
    );
    pg.send(&message("s3:ObjectCreated:Put", "b/3"))
        .await
        .unwrap();
    assert_eq!(
        server.startups().len(),
        connections,
        "the connection is kept"
    );
    server.hang_up();
    pg.send(&message("s3:ObjectCreated:Put", "b/4"))
        .await
        .unwrap();
    assert_eq!(server.startups().len(), connections + 1);
    assert_eq!(server.rows("events", 3).await.len(), 3);

    for pretence in [PgImpostor::WrongProof, PgImpostor::NoProof] {
        let impostor = PostgresServer::start(PostgresSetup {
            impostor: Some(pretence),
            ..PostgresSetup::default()
        })
        .await;
        let err = postgres(&impostor, Format::Namespace)
            .test()
            .await
            .unwrap_err();
        assert!(err.contains("it isn't the server"), "{pretence:?}: {err}");
        assert!(impostor.statements().is_empty(), "{pretence:?}");
    }

    let clear = PostgresServer::start(PostgresSetup {
        auth: PgAuth::Password,
        ..PostgresSetup::default()
    })
    .await;
    let err = postgres(&clear, Format::Namespace)
        .test()
        .await
        .unwrap_err();
    assert!(err.contains("in the clear"), "{err}");
    assert!(clear.statements().is_empty());

    let trust = PostgresServer::start(PostgresSetup {
        auth: PgAuth::Trust,
        ..PostgresSetup::default()
    })
    .await;
    let mut pg = postgres(&trust, Format::Access);
    pg.password = None;
    pg.test().await.unwrap();
}

/// PostgreSQL over TLS, asked for before the startup message: the server is verified with
/// the operator's CA, a password in the clear is then sent, and a server without TLS or
/// one the CA didn't sign is refused.
#[tokio::test]
async fn postgres_is_reached_over_tls() {
    use crate::testing::{PgAuth, PostgresServer, PostgresSetup};
    let (acceptor, ca_pem) = test_tls();
    let server = PostgresServer::start(PostgresSetup {
        auth: PgAuth::Password,
        tls: Some(acceptor),
        ..PostgresSetup::default()
    })
    .await;
    let mut pg = postgres(&server, Format::Namespace);
    pg.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert!(pg.shown().ends_with("(namespace, TLS)"), "{}", pg.shown());
    pg.send(&message("s3:ObjectCreated:Put", "b/k"))
        .await
        .unwrap();
    assert_eq!(server.rows("events", 1).await.len(), 1);
    assert!(server.startups().iter().all(|s| s.tls && s.signed_in));

    pg.tls = Some(tls_config(None, None).unwrap());
    let err = pg.test().await.unwrap_err();
    assert!(err.contains("TLS failed"), "{err}");

    let plain = PostgresServer::start(PostgresSetup::default()).await;
    let mut pg = postgres(&plain, Format::Namespace);
    pg.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    let err = pg.test().await.unwrap_err();
    assert_eq!(err, "the server doesn't take TLS");
}

fn mysql(server: &crate::testing::MysqlServer, format: Format) -> Mysql {
    let mut db = Mysql::new(server.address(), "s3", "events", format, "teifs").unwrap();
    db.password = Some(Zeroizing::new("pw".into()));
    db
}

/// MySQL targets in the `namespace` format: the table is made when the connection is,
/// with `MinIO`'s columns; each event sets its object's row by a statement prepared once
/// per connection, its values bound (a key with a quote is only a value), and a removal
/// deletes it. The server had the user cached, so only a proof of the password was sent.
#[tokio::test]
async fn mysql_keeps_a_row_per_object() {
    use crate::testing::{MyPassword, MysqlServer, MysqlSetup};
    let server = MysqlServer::start(MysqlSetup::default()).await;
    let db = mysql(&server, Format::Namespace);
    db.test().await.unwrap();
    let (columns, rows) = server.table("events").unwrap();
    assert!(
        columns.starts_with("(key_name VARCHAR(3072) NOT NULL, key_hash CHAR(64)"),
        "{columns}"
    );
    assert!(rows.is_empty());
    for (name, key) in [
        ("s3:ObjectCreated:Put", "b/it's"),
        ("s3:ObjectCreated:Put", "b/k"),
        ("s3:ObjectCreated:Copy", "b/it's"),
        ("s3:ObjectRemoved:Delete", "b/k"),
    ] {
        db.send(&message(name, key)).await.unwrap();
    }
    let rows = server.rows("events", 1).await;
    assert_eq!(rows[0][0], "b/it's");
    let value: serde_json::Value = serde_json::from_str(&rows[0][1]).unwrap();
    assert_eq!(value["Records"][0]["eventName"], "ObjectCreated:Copy");
    assert_eq!(server.prepares(), 2, "one upsert and one delete");
    let statements = server.statements();
    assert!(statements.iter().all(|(sql, _)| !sql.contains("it's")));
    assert_eq!(
        statements.last().unwrap(),
        &(
            "DELETE FROM events WHERE key_hash = SHA2(?, 256);".to_owned(),
            vec!["b/k".to_owned()]
        )
    );
    let startups = server.startups();
    assert_eq!(startups.len(), 1);
    let startup = &startups[0];
    assert_eq!(
        (
            startup.user.as_str(),
            startup.database.as_str(),
            startup.collation,
            startup.plugin.as_str(),
            startup.password,
            startup.signed_in,
            startup.tls
        ),
        (
            "teifs",
            "s3",
            45,
            "caching_sha2_password",
            MyPassword::Proof,
            true,
            false
        )
    );
}

/// On `MariaDB`, which takes no generated primary key, the `namespace` table keys the
/// object's hash uniquely instead, and rows are set and deleted the same way.
#[tokio::test]
async fn mysql_makes_mariadbs_table_its_way() {
    use crate::testing::{MysqlServer, MysqlSetup};
    let server = MysqlServer::start(MysqlSetup {
        mariadb: true,
        ..MysqlSetup::default()
    })
    .await;
    let db = mysql(&server, Format::Namespace);
    for (name, key) in [
        ("s3:ObjectCreated:Put", "b/a"),
        ("s3:ObjectCreated:Put", "b/k"),
        ("s3:ObjectRemoved:Delete", "b/a"),
    ] {
        db.send(&message(name, key)).await.unwrap();
    }
    assert_eq!(server.rows("events", 1).await[0][0], "b/k");
    let (columns, _) = server.table("events").unwrap();
    assert!(
        columns.contains("STORED, value JSON, UNIQUE KEY key_hash (key_hash))"),
        "{columns}"
    );
}

/// MySQL targets in the `access` format, signed in as a `mysql_native_password` user after
/// the server switches to that plugin: a table that's there is used as it is, and each event
/// is a row of its time (a `DATETIME`, in UTC) and itself.
#[tokio::test]
async fn mysql_adds_a_row_per_event() {
    use crate::testing::{MyAuth, MysqlServer, MysqlSetup};
    let server = MysqlServer::start(MysqlSetup {
        auth: MyAuth::Native,
        greeting: Some(MyAuth::CachingSha2),
        tables: [("`S3 Log`".to_owned(), "(given)".to_owned())].into(),
        ..MysqlSetup::default()
    })
    .await;
    let mut db = mysql(&server, Format::Access);
    db.table = "`S3 Log`".into();
    for (name, key) in [
        ("s3:ObjectCreated:Put", "b/k"),
        ("s3:ObjectRemoved:Delete", "b/k"),
    ] {
        db.send(&message(name, key)).await.unwrap();
    }
    let rows = server.rows("`S3 Log`", 2).await;
    assert_eq!(server.table("`S3 Log`").unwrap().0, "(given)");
    assert_eq!(rows[1][0], "2026-09-30 12:00:00.000");
    let event: serde_json::Value = serde_json::from_str(&rows[1][1]).unwrap();
    assert_eq!(event["EventName"], "s3:ObjectRemoved:Delete");
    assert_eq!(server.startups()[0].plugin, "mysql_native_password");
    assert!(
        !server
            .statements()
            .iter()
            .any(|(sql, _)| sql.starts_with("CREATE"))
    );
}

/// A server that wants the whole password without TLS (`caching_sha2_password` before it
/// has the user cached, `sha256_password`) gets it only encrypted with its RSA key: the one
/// the operator gave, or one asked for when that's allowed; else the target says how to
/// fix it. A password in the clear is sent only over TLS.
#[tokio::test]
async fn mysql_sends_the_whole_password_only_safely() {
    use crate::testing::{MyAuth, MyPassword, MysqlServer, MysqlSetup};
    let server = MysqlServer::start(MysqlSetup {
        cached: false,
        ..MysqlSetup::default()
    })
    .await;
    let mut db = mysql(&server, Format::Namespace);
    let err = db.test().await.unwrap_err();
    assert!(err.contains("server_public_key=PATH"), "{err}");
    db.server_key = ServerKey::from_pem(server.public_key_pem().as_bytes()).unwrap();
    db.test().await.unwrap();
    // Cached now: the next sign-in is only a proof.
    db.test().await.unwrap();
    server.flush_cache();
    db.server_key = ServerKey::Ask;
    db.test().await.unwrap();
    let sent: Vec<MyPassword> = server.startups().iter().map(|s| s.password).collect();
    // The first try, without a key, hung up without sending it.
    assert_eq!(
        sent,
        [
            MyPassword::Encrypted { asked_key: false },
            MyPassword::Proof,
            MyPassword::Encrypted { asked_key: true },
        ]
    );
    // Another server's key doesn't open it.
    let other = MysqlServer::start(MysqlSetup::default()).await;
    server.flush_cache();
    db.server_key = ServerKey::from_pem(other.public_key_pem().as_bytes()).unwrap();
    let err = db.test().await.unwrap_err();
    assert!(err.contains("refused the user or password"), "{err}");

    let sha256 = MysqlServer::start(MysqlSetup {
        auth: MyAuth::Sha256,
        ..MysqlSetup::default()
    })
    .await;
    let mut db = mysql(&sha256, Format::Namespace);
    assert!(db.test().await.unwrap_err().contains("server_public_key"));
    db.server_key = ServerKey::Ask;
    db.test().await.unwrap();
    assert_eq!(
        sha256.startups()[0].password,
        MyPassword::Encrypted { asked_key: true }
    );

    let clear = MysqlServer::start(MysqlSetup {
        auth: MyAuth::Clear,
        greeting: Some(MyAuth::Native),
        ..MysqlSetup::default()
    })
    .await;
    let err = mysql(&clear, Format::Namespace).test().await.unwrap_err();
    assert!(err.contains("in the clear"), "{err}");
    assert!(clear.startups().iter().all(|s| !s.signed_in));

    // A plugin TeiFS doesn't speak is named, rather than answered with another's proof.
    let ed25519 = MysqlServer::start(MysqlSetup {
        auth: MyAuth::Ed25519,
        greeting: Some(MyAuth::Native),
        ..MysqlSetup::default()
    })
    .await;
    let err = mysql(&ed25519, Format::Namespace).test().await.unwrap_err();
    assert!(err.contains("`client_ed25519`"), "{err}");

    // A server older than MySQL 5.7's handshake is named.
    let old = MysqlServer::start(MysqlSetup {
        lacks: crate::mysql::wire::capability::PLUGIN_AUTH,
        ..MysqlSetup::default()
    })
    .await;
    let err = mysql(&old, Format::Namespace).test().await.unwrap_err();
    assert!(err.contains("older than MySQL 5.7"), "{err}");
}

/// What a MySQL server refuses is named: the password, the database, a table it may not
/// read (not made again), and a statement (which keeps the connection); a connection the
/// server closed is made again.
#[tokio::test]
async fn mysql_names_what_the_server_refuses() {
    use crate::testing::{MysqlServer, MysqlSetup};
    let server = MysqlServer::start(MysqlSetup::default()).await;
    let mut db = mysql(&server, Format::Namespace);
    db.password = Some(Zeroizing::new("wrong".into()));
    let err = db.test().await.unwrap_err();
    assert!(
        err.contains("refused the user or password") && err.contains("1045"),
        "{err}"
    );
    let mut db = mysql(&server, Format::Namespace);
    db.database = "other".into();
    let err = db.test().await.unwrap_err();
    assert!(err.contains("1049") && err.contains("'other'"), "{err}");

    server.refuse(1);
    let err = mysql(&server, Format::Namespace).test().await.unwrap_err();
    assert!(err.contains("1142"), "{err}");
    assert!(
        !server
            .statements()
            .iter()
            .any(|(sql, _)| sql.starts_with("CREATE"))
    );

    let db = mysql(&server, Format::Namespace);
    db.send(&message("s3:ObjectCreated:Put", "b/1"))
        .await
        .unwrap();
    let connections = server.startups().len();
    server.refuse(1);
    let err = db
        .send(&message("s3:ObjectCreated:Put", "b/2"))
        .await
        .unwrap_err();
    assert!(err.contains("1142") && err.contains("denied"), "{err}");
    db.send(&message("s3:ObjectCreated:Put", "b/3"))
        .await
        .unwrap();
    assert_eq!(
        server.startups().len(),
        connections,
        "the connection is kept"
    );
    server.hang_up();
    db.send(&message("s3:ObjectCreated:Put", "b/4"))
        .await
        .unwrap();
    assert_eq!(server.startups().len(), connections + 1);
    assert_eq!(server.rows("events", 3).await.len(), 3);
}

/// MySQL over TLS: the server is verified with the operator's CA, the whole password is
/// then sent in the clear, and a server without TLS or one the CA didn't sign is refused.
#[tokio::test]
async fn mysql_is_reached_over_tls() {
    use crate::testing::{MyAuth, MyPassword, MysqlServer, MysqlSetup};
    let (acceptor, ca_pem) = test_tls();
    let server = MysqlServer::start(MysqlSetup {
        cached: false,
        tls: Some(acceptor.clone()),
        ..MysqlSetup::default()
    })
    .await;
    let mut db = mysql(&server, Format::Namespace);
    db.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert!(db.shown().ends_with("(namespace, TLS)"), "{}", db.shown());
    db.send(&message("s3:ObjectCreated:Put", "b/k"))
        .await
        .unwrap();
    assert_eq!(server.rows("events", 1).await.len(), 1);
    let startup = &server.startups()[0];
    assert!(startup.tls && startup.signed_in);
    assert_eq!(startup.password, MyPassword::Clear);

    // A password longer than a one-byte length, in the first answer.
    let long = "p".repeat(300);
    let clear = MysqlServer::start(MysqlSetup {
        auth: MyAuth::Clear,
        login: ("teifs".into(), long.clone()),
        tls: Some(acceptor),
        ..MysqlSetup::default()
    })
    .await;
    let mut db = mysql(&clear, Format::Namespace);
    db.password = Some(Zeroizing::new(long));
    db.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    db.test().await.unwrap();

    db.tls = Some(tls_config(None, None).unwrap());
    let err = db.test().await.unwrap_err();
    assert!(err.contains("TLS failed"), "{err}");

    let plain = MysqlServer::start(MysqlSetup::default()).await;
    let mut db = mysql(&plain, Format::Namespace);
    db.tls = Some(tls_config(Some(ca_pem.as_bytes()), None).unwrap());
    assert_eq!(db.test().await.unwrap_err(), "the server doesn't take TLS");
}
