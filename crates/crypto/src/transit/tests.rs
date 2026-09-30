//! The transit backend against a fake engine that behaves like Vault's: token checks,
//! versions, rotation, associated data, and encrypt creating missing keys (which the
//! backend must not rely on).

use std::{
    collections::HashMap,
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

const TOKEN: &str = "test-token-not-real";

#[derive(Default)]
struct FakeEngine {
    /// Key name → latest version.
    keys: HashMap<String, u32>,
}

fn reply(status: StatusCode, body: Option<Value>) -> Response<Full<Bytes>> {
    let bytes = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    Response::builder()
        .status(status)
        .body(Full::new(bytes))
        .unwrap()
}

async fn handle(
    engine: Arc<Mutex<FakeEngine>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req
        .headers()
        .get("X-Vault-Token")
        .and_then(|v| v.to_str().ok())
        != Some(TOKEN)
    {
        return Ok(reply(StatusCode::FORBIDDEN, None));
    }
    let method = req.method().as_str().to_owned();
    let path = req
        .uri()
        .path()
        .trim_start_matches("/v1/transit/")
        .to_owned();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let mut engine = engine.lock().unwrap();
    let parts: Vec<&str> = path.split('/').collect();
    let response = match (method.as_str(), parts.as_slice()) {
        ("LIST", ["keys"]) if engine.keys.is_empty() => reply(StatusCode::NOT_FOUND, None),
        ("LIST", ["keys"]) => {
            let names: Vec<_> = engine.keys.keys().cloned().collect();
            reply(StatusCode::OK, Some(json!({"data": {"keys": names}})))
        }
        ("GET", ["keys", name]) => match engine.keys.get(*name) {
            Some(v) => reply(
                StatusCode::OK,
                Some(
                    json!({"data": {"latest_version": v, "keys": {v.to_string(): 1_790_000_000}}}),
                ),
            ),
            None => reply(StatusCode::NOT_FOUND, None),
        },
        ("POST", ["keys", name]) => {
            engine.keys.entry((*name).to_owned()).or_insert(1);
            reply(StatusCode::NO_CONTENT, None)
        }
        ("POST", ["keys", name, "rotate"]) => match engine.keys.get_mut(*name) {
            Some(v) => {
                *v += 1;
                reply(StatusCode::NO_CONTENT, None)
            }
            None => reply(StatusCode::NOT_FOUND, None),
        },
        ("POST", ["encrypt", name]) => {
            // Like Vault: encrypting with a missing key creates it.
            let version = *engine.keys.entry((*name).to_owned()).or_insert(1);
            let blob = STANDARD.encode(json.to_string());
            reply(
                StatusCode::OK,
                Some(json!({"data": {"ciphertext": format!("vault:v{version}:{blob}")}})),
            )
        }
        ("POST", ["decrypt", _]) => {
            let ciphertext = json["ciphertext"].as_str().unwrap_or_default();
            let blob = ciphertext.splitn(3, ':').nth(2).unwrap_or_default();
            let sealed: Value = serde_json::from_slice(&STANDARD.decode(blob).unwrap_or_default())
                .unwrap_or(Value::Null);
            if sealed["associated_data"] == json["associated_data"] {
                reply(
                    StatusCode::OK,
                    Some(json!({"data": {"plaintext": sealed["plaintext"]}})),
                )
            } else {
                reply(
                    StatusCode::BAD_REQUEST,
                    Some(json!({"errors": ["cipher: message authentication failed"]})),
                )
            }
        }
        _ => reply(StatusCode::NOT_FOUND, None),
    };
    Ok(response)
}

/// Starts a fake engine; its address.
async fn fake_engine() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let engine = Arc::new(Mutex::new(FakeEngine::default()));
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let engine = engine.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| handle(engine.clone(), req));
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    address
}

fn ctx(object: &str) -> Context {
    Context::object("drive", "bucket", object)
}

#[tokio::test]
async fn seals_through_the_engine_bound_to_the_context() {
    let address = fake_engine().await;
    let kms = TransitKms::new(&address, "transit", TOKEN.into(), None).unwrap();
    kms.create_key(DEFAULT_KEY).await.unwrap();
    let (key, sealed) = kms.generate(None, &ctx("o1")).await.unwrap();
    assert_eq!(sealed.provider, TRANSIT);
    assert_eq!(
        (sealed.kms_key.as_str(), sealed.kms_version),
        (DEFAULT_KEY, 1)
    );
    assert!(
        String::from_utf8(sealed.sealed.clone())
            .unwrap()
            .starts_with("vault:v1:")
    );
    assert_eq!(kms.unseal(&sealed, &ctx("o1")).await.unwrap(), key);
    // Another object's context doesn't open it.
    assert!(matches!(
        kms.unseal(&sealed, &ctx("o2")).await,
        Err(CryptoError::Authentication)
    ));
    // Nor does TeiFS's own unsealing.
    assert!(crate::unseal(&[0; 32], &ctx("o1"), &sealed).is_err());
}

#[tokio::test]
async fn missing_keys_are_never_created_by_writes() {
    let address = fake_engine().await;
    let kms = TransitKms::new(&address, "transit", TOKEN.into(), None).unwrap();
    assert!(matches!(
        kms.generate(Some("typo"), &ctx("o")).await,
        Err(CryptoError::NoSuchKey(name)) if name == "typo"
    ));
    assert!(kms.keys().await.unwrap().is_empty());
}

#[tokio::test]
async fn keys_are_listed_created_and_rotated() {
    let address = fake_engine().await;
    let kms = TransitKms::new(&address, "transit/", TOKEN.into(), Some("team".into())).unwrap();
    kms.create_key("photos").await.unwrap();
    assert!(kms.create_key("photos").await.is_err());
    let (key, old) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(kms.rotate_key("photos").await.unwrap().version, 2);
    let (_, new) = kms.generate(Some("photos"), &ctx("o")).await.unwrap();
    assert_eq!(new.kms_version, 2);
    // Keys sealed by older versions still open.
    assert_eq!(kms.unseal(&old, &ctx("o")).await.unwrap(), key);
    // And can be sealed again under the newest version.
    let resealed = kms.seal(Some("photos"), &ctx("o"), &key).await.unwrap();
    assert_eq!(resealed.kms_version, 2);
    assert_eq!(kms.unseal(&resealed, &ctx("o")).await.unwrap(), key);
    let keys = kms.keys().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!((keys[0].name.as_str(), keys[0].version), ("photos", 2));
}

#[tokio::test]
async fn a_wrong_token_is_reported() {
    let address = fake_engine().await;
    let kms = TransitKms::new(&address, "transit", "wrong".into(), None).unwrap();
    assert!(matches!(
        kms.generate(None, &ctx("o")).await,
        Err(CryptoError::Kms(message)) if message.contains("403")
    ));
    assert!(!format!("{kms:?}").contains("wrong"));
}
