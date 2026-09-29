//! An OpenID Connect provider on a loopback port, for web identity tests.

use std::time::SystemTime;

/// An OpenID Connect provider on a loopback port, signing with an ECDSA P-256 key: its
/// URL, and a token it issues for `sub` with `claims` besides the usual ones.
pub struct Idp {
    pub url: String,
    key: aws_lc_rs::signature::EcdsaKeyPair,
}

impl Idp {
    pub async fn start() -> Self {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let point = key.public_key().as_ref();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let discovery = format!(r#"{{"issuer":"{url}","jwks_uri":"{url}/keys"}}"#);
        let keys = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"k1","use":"sig","alg":"ES256","x":"{}","y":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(&point[1..33]),
            URL_SAFE_NO_PAD.encode(&point[33..])
        );
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (discovery, keys) = (discovery.clone(), keys.clone());
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buffer[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    let body = match request.split(' ').nth(1) {
                        Some("/.well-known/openid-configuration") => discovery,
                        Some("/keys") => keys,
                        _ => String::new(),
                    };
                    let status = if body.is_empty() { 404 } else { 200 };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        Self { url, key }
    }

    /// A token it issues for `sub` with `claims` (`,"k":"v"`) besides `iss`, `sub`,
    /// `aud` (`sts.amazonaws.com`), `iat` and `exp` (in five minutes).
    pub fn token(&self, sub: &str, claims: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(format!(
                r#"{{"iss":"{}","sub":"{sub}","aud":"sts.amazonaws.com","iat":{now},"exp":{}{claims}}}"#,
                self.url,
                now + 300
            ))
        );
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let signature = self.key.sign(&rng, signed.as_bytes()).unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}
