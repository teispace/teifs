//! The AWS KMS backend against a fake service that behaves like AWS KMS: aliases,
//! encryption contexts, rotations that only take key ids or ARNs, pages, and AWS's errors.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};

use super::*;

const ACCOUNT: &str = "111122223333";

struct FakeKey {
    rotations: u32,
}

#[derive(Default)]
struct FakeKms {
    /// Key id → key.
    keys: BTreeMap<String, FakeKey>,
    /// Alias name → key id.
    aliases: BTreeMap<String, String>,
    /// Refuse `ListKeyRotations`, as a narrow key policy does.
    deny_rotations: bool,
    /// Make `CreateAlias` find the name taken, as when another server won the race.
    alias_race: bool,
    /// Key ids scheduled for deletion.
    deleted: Vec<String>,
}

fn arn(id: &str) -> String {
    format!("arn:aws:kms:us-east-1:{ACCOUNT}:key/{id}")
}

fn error(code: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/x-amz-json-1.1")
        .body(Full::new(Bytes::from(
            json!({"__type": code, "message": format!("fake {code}")}).to_string(),
        )))
        .unwrap()
}

fn ok(body: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .header("content-type", "application/x-amz-json-1.1")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

impl FakeKms {
    /// The key a `KeyId` names: an id, a key ARN, an alias or an alias ARN.
    fn resolve(&self, key_id: &str) -> Option<String> {
        let name = key_id.rsplit_once(':').map_or(key_id, |(_, rest)| rest);
        let id = match name.strip_prefix("key/") {
            Some(id) => id.to_owned(),
            None if name.starts_with("alias/") => self.aliases.get(name)?.clone(),
            None => name.to_owned(),
        };
        self.keys.contains_key(&id).then_some(id)
    }

    /// The key a rotation call names: AWS takes key ids and ARNs only.
    fn resolve_for_rotation(&self, key_id: &str) -> Result<String, &'static str> {
        if key_id.contains("alias/") {
            return Err("ValidationException");
        }
        self.resolve(key_id).ok_or("NotFoundException")
    }

    fn metadata(id: &str) -> Value {
        json!({"KeyId": id, "Arn": arn(id), "CreationDate": 1_790_000_000.5, "KeyState": "Enabled",
               "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT"})
    }

    fn call(&mut self, operation: &str, body: &Value) -> Response<Full<Bytes>> {
        let key_id = body["KeyId"].as_str().unwrap_or_default();
        match operation {
            "DescribeKey" => match self.resolve(key_id) {
                Some(id) => ok(&json!({"KeyMetadata": Self::metadata(&id)})),
                None => error("NotFoundException"),
            },
            "Encrypt" => {
                let Some(id) = self.resolve(key_id) else {
                    return error("NotFoundException");
                };
                let blob = json!({
                    "key": id,
                    "material": self.keys[&id].rotations,
                    "plain": body["Plaintext"],
                    "context": body.get("EncryptionContext").cloned().unwrap_or(json!({})),
                });
                ok(
                    &json!({"CiphertextBlob": STANDARD.encode(blob.to_string()), "KeyId": arn(&id),
                           "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}),
                )
            }
            "Decrypt" => {
                let sealed: Value = STANDARD
                    .decode(body["CiphertextBlob"].as_str().unwrap_or_default())
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(Value::Null);
                let context = body.get("EncryptionContext").cloned().unwrap_or(json!({}));
                if sealed.is_null() || sealed["context"] != context {
                    return error("InvalidCiphertextException");
                }
                let id = sealed["key"].as_str().unwrap_or_default();
                if !key_id.is_empty() && self.resolve(key_id).as_deref() != Some(id) {
                    return error("IncorrectKeyException");
                }
                ok(&json!({"Plaintext": sealed["plain"], "KeyId": arn(id)}))
            }
            "CreateKey" => {
                assert_eq!(body["KeySpec"], "SYMMETRIC_DEFAULT");
                assert_eq!(body["KeyUsage"], "ENCRYPT_DECRYPT");
                let id = format!("1234abcd-12ab-34cd-56ef-{:012}", self.keys.len());
                self.keys.insert(id.clone(), FakeKey { rotations: 0 });
                ok(&json!({"KeyMetadata": Self::metadata(&id)}))
            }
            "CreateAlias" => {
                let name = body["AliasName"].as_str().unwrap_or_default().to_owned();
                if self.alias_race || self.aliases.contains_key(&name) {
                    return error("AlreadyExistsException");
                }
                let target = body["TargetKeyId"].as_str().unwrap_or_default().to_owned();
                self.aliases.insert(name, target);
                ok(&json!({}))
            }
            "ScheduleKeyDeletion" => {
                assert_eq!(body["PendingWindowInDays"], 7);
                self.deleted.push(key_id.to_owned());
                ok(&json!({"KeyId": key_id}))
            }
            "RotateKeyOnDemand" => match self.resolve_for_rotation(key_id) {
                Ok(id) => {
                    self.keys.get_mut(&id).unwrap().rotations += 1;
                    ok(&json!({"KeyId": id}))
                }
                Err(code) => error(code),
            },
            "ListKeyRotations" => self.list_rotations(key_id, body),
            "ListAliases" => self.list_aliases(body),
            other => panic!("unexpected {other}"),
        }
    }

    /// A rotation per page, so paging is exercised.
    fn list_rotations(&self, key_id: &str, body: &Value) -> Response<Full<Bytes>> {
        if self.deny_rotations {
            return error("AccessDeniedException");
        }
        let id = match self.resolve_for_rotation(key_id) {
            Ok(id) => id,
            Err(code) => return error(code),
        };
        let at: u32 = body["Marker"].as_str().map_or(0, |m| m.parse().unwrap());
        let total = self.keys[&id].rotations;
        if at >= total {
            return ok(&json!({"Rotations": [], "Truncated": false}));
        }
        let rotation = json!({"KeyId": id, "RotationDate": 1_790_000_000 + at,
                              "RotationType": "ON_DEMAND"});
        let more = at + 1 < total;
        let mut page = json!({"Rotations": [rotation], "Truncated": more});
        if more {
            page["NextMarker"] = json!((at + 1).to_string());
        }
        ok(&page)
    }

    /// Two aliases per page, with AWS's own and an unattached alias among them.
    fn list_aliases(&self, body: &Value) -> Response<Full<Bytes>> {
        let mut all: Vec<Value> = vec![
            json!({"AliasName": "alias/aws/s3", "TargetKeyId": "aws-owned", "CreationDate": 1}),
            json!({"AliasName": "alias/unattached"}),
        ];
        all.extend(self.aliases.iter().map(|(name, id)| {
            json!({"AliasName": name, "AliasArn": format!("arn:aws:kms:us-east-1:{ACCOUNT}:{name}"),
                   "TargetKeyId": id, "CreationDate": 1_790_000_000.25})
        }));
        let at: usize = body["Marker"].as_str().map_or(0, |m| m.parse().unwrap());
        let end = (at + 2).min(all.len());
        let more = end < all.len();
        let mut page = json!({"Aliases": all[at..end], "Truncated": more});
        if more {
            page["NextMarker"] = json!(end.to_string());
        }
        ok(&page)
    }
}

async fn handle(
    kms: Arc<Mutex<FakeKms>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    assert!(
        req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256") && v.contains("/kms/aws4_request")),
        "requests are signed for KMS"
    );
    let operation = req
        .headers()
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("TrentService."))
        .unwrap_or_default()
        .to_owned();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Ok(kms.lock().unwrap().call(&operation, &json))
}

/// Starts a fake AWS KMS; the backend and the fake's state.
async fn fake_kms() -> (AwsKms, Arc<Mutex<FakeKms>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(FakeKms::default()));
    let kms = state.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let kms = kms.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| handle(kms.clone(), req));
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .region(aws_sdk_kms::config::Region::new("us-east-1"))
        .endpoint_url(address)
        .credentials_provider(aws_sdk_kms::config::Credentials::new(
            "AKIDTEST",
            "not-a-real-secret-only-for-tests",
            None,
            None,
            "test",
        ))
        .build();
    (
        AwsKms::with_client(Client::from_conf(config), "us-east-1".to_owned()),
        state,
    )
}

fn ctx(object: &str) -> Context {
    Context::object("drive", "bucket", object)
}

#[tokio::test]
async fn seals_through_aws_kms_bound_to_the_context() {
    let (kms, _) = fake_kms().await;
    assert_eq!(kms.region(), "us-east-1");
    kms.create_key(DEFAULT_KEY).await.unwrap();
    let (key, sealed) = kms.generate(None, &ctx("o1")).await.unwrap();
    assert_eq!(sealed.provider, AWS_KMS);
    assert_eq!(
        (sealed.kms_key.as_str(), sealed.kms_version),
        (DEFAULT_KEY, 1)
    );
    assert!(sealed.salt.is_empty());
    assert_eq!(kms.unseal(&sealed, &ctx("o1")).await.unwrap(), key);
    // Another object's context doesn't open it.
    assert!(matches!(
        kms.unseal(&sealed, &ctx("o2")).await,
        Err(CryptoError::Authentication)
    ));
    // Nor does TeiFS's own unsealing, nor another provider's seal.
    assert!(crate::unseal(&[0; 32], &ctx("o1"), &sealed).is_err());
    let transit = SealedKey {
        provider: crate::TRANSIT.to_owned(),
        ..sealed.clone()
    };
    assert!(matches!(
        kms.unseal(&transit, &ctx("o1")).await,
        Err(CryptoError::Kms(m)) if m.contains("AWS KMS")
    ));
    // A ciphertext that isn't one doesn't open.
    let garbage = SealedKey {
        sealed: b"not a ciphertext".to_vec(),
        ..sealed
    };
    assert!(matches!(
        kms.unseal(&garbage, &ctx("o1")).await,
        Err(CryptoError::Authentication)
    ));
}

#[tokio::test]
async fn an_empty_context_is_sent_as_none() {
    let (kms, _) = fake_kms().await;
    kms.create_key("plain").await.unwrap();
    let (key, sealed) = kms
        .generate(Some("plain"), &Context::default())
        .await
        .unwrap();
    assert_eq!(kms.unseal(&sealed, &Context::default()).await.unwrap(), key);
    assert_eq!(encryption_context(&Context::default()), None);
    assert_eq!(encryption_context(&ctx("o")).unwrap()["teifs:object"], "o");
}

#[tokio::test]
async fn missing_keys_are_reported_by_name() {
    let (kms, _) = fake_kms().await;
    assert!(matches!(
        kms.generate(Some("typo"), &ctx("o")).await,
        Err(CryptoError::NoSuchKey(name)) if name == "typo"
    ));
    assert!(matches!(
        kms.rotate_key("typo").await,
        Err(CryptoError::NoSuchKey(name)) if name == "typo"
    ));
    assert!(kms.keys().await.unwrap().is_empty());
}

#[tokio::test]
async fn keys_are_created_listed_and_rotated() {
    let (kms, state) = fake_kms().await;
    let created = kms.create_key("photos").await.unwrap();
    assert_eq!(
        (created.name.as_str(), created.version, created.created_ms),
        ("photos", 1, 1_790_000_000_500)
    );
    assert!(matches!(
        kms.create_key("photos").await,
        Err(CryptoError::Kms(m)) if m.contains("already exists")
    ));
    assert!(kms.create_key("not/a name").await.is_err());
    kms.create_key("videos").await.unwrap();
    kms.create_key("audio").await.unwrap();

    let (key, old) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(old.kms_version, 1);
    let rotated = kms.rotate_key("photos").await.unwrap();
    // The newest version was made just now.
    assert_eq!(rotated.version, 2);
    assert!(rotated.created_ms > 1_790_000_000_500);
    assert_eq!(kms.rotate_key("photos").await.unwrap().version, 3);
    // Seals after a rotation record the version the rotations make.
    let (_, new) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(new.kms_version, 3);
    // Keys sealed under older material still open.
    assert_eq!(kms.unseal(&old, &ctx("o")).await.unwrap(), key);

    // Aliases are listed across pages, without AWS's own or unattached ones.
    let keys = kms.keys().await.unwrap();
    let listed: Vec<_> = keys
        .iter()
        .map(|k| (k.name.as_str(), k.version, k.created_ms))
        .collect();
    assert_eq!(
        listed,
        [
            // A key's own date, or its newest rotation's: never the alias's.
            ("audio", 1, 1_790_000_000_500),
            ("photos", 3, 1_790_000_001_000),
            ("videos", 1, 1_790_000_000_500)
        ]
    );
    assert!(state.lock().unwrap().deleted.is_empty());
}

#[tokio::test]
async fn versions_are_remembered_for_an_hour() {
    let (kms, state) = fake_kms().await;
    kms.create_key("photos").await.unwrap();
    // A rotation AWS made on its own schedule isn't seen until the version is recounted.
    let id = state.lock().unwrap().aliases["alias/photos"].clone();
    state.lock().unwrap().keys.get_mut(&id).unwrap().rotations = 1;
    let (_, sealed) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(sealed.kms_version, 1);
    kms.versions()
        .insert("photos".to_owned(), (1, Instant::now()));
    let (_, sealed) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(sealed.kms_version, 2);
}

#[tokio::test]
async fn keys_whose_rotations_cant_be_listed_are_at_version_one() {
    let (kms, state) = fake_kms().await;
    kms.create_key("photos").await.unwrap();
    kms.rotate_key("photos").await.unwrap();
    state.lock().unwrap().deny_rotations = true;
    let (_, sealed) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(sealed.kms_version, 1);
    assert_eq!(kms.keys().await.unwrap()[0].version, 1);
}

#[tokio::test]
async fn a_lost_alias_race_deletes_the_new_key() {
    let (kms, state) = fake_kms().await;
    state.lock().unwrap().alias_race = true;
    assert!(matches!(
        kms.create_key("photos").await,
        Err(CryptoError::Kms(m)) if m.contains("already exists")
    ));
    let state = state.lock().unwrap();
    assert_eq!(state.deleted, ["1234abcd-12ab-34cd-56ef-000000000000"]);
}

#[tokio::test]
async fn ids_arns_and_aliases_name_keys_too() {
    let (kms, state) = fake_kms().await;
    kms.create_key("photos").await.unwrap();
    let id = state.lock().unwrap().aliases["alias/photos"].clone();
    for name in [id.clone(), arn(&id), "alias/photos".to_owned()] {
        let (key, sealed) = kms.generate(Some(&name), &ctx("o")).await.unwrap();
        assert_eq!(sealed.kms_key, name);
        assert_eq!(kms.unseal(&sealed, &ctx("o")).await.unwrap(), key);
    }
}

#[test]
fn names_become_aliases_unless_they_name_a_key() {
    assert_eq!(key_id("photos"), "alias/photos");
    assert_eq!(key_id("teifs-default"), "alias/teifs-default");
    for given in [
        "1234abcd-12ab-34cd-56ef-1234567890ab",
        "mrk-1234abcd12ab34cd56ef1234567890ab",
        "alias/photos",
        "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "arn:aws:kms:us-east-2:111122223333:alias/photos",
    ] {
        assert_eq!(key_id(given), given);
    }
    for not_an_id in [
        "1234abcd-12ab-34cd-56ef-1234567890a",
        "1234abcd-12ab-34cd-56ef-1234567890ag",
        "1234abcd12ab-34cd-56ef-1234567890ab-",
        "mrk-1234",
        "mrk-1234abcd12ab34cd56ef1234567890ag",
    ] {
        assert!(!is_key_id(not_an_id), "{not_an_id}");
    }
}
