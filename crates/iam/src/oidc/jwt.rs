//! Web identity tokens: JSON Web Tokens (RFC 7519) signed with a JSON Web Signature
//! (RFC 7515), and the JSON Web Keys (RFC 7517) that check them.
//!
//! Only asymmetric signatures are taken, as AWS takes them: RSA (`RS256`/`384`/`512`,
//! and `PS…` with PSS) of 2048 to 8192 bits, and ECDSA on P-256, P-384 and P-521
//! (`ES256`/`384`/`512`). `none`, and `HS…` (whose key would be the public key, a known
//! way to forge tokens), are refused before any key is looked at. A key is used only for
//! the algorithm it's for: its `kty` and curve must fit, and its `alg` and `use`, when it
//! has them, must say so. Headers and claims are read strictly: a member named twice is
//! refused, so no two readers see different claims.

use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use teifs_policy::Json;

/// The longest token AWS takes (`WebIdentityToken`), and so the longest decoded here.
pub(crate) const MAX_TOKEN: usize = 20_000;
/// The most keys a key set may have; the rest are ignored.
const MAX_KEYS: usize = 100;

/// Why a token isn't accepted: AWS's `InvalidIdentityToken`, with a message saying why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct Invalid(pub(crate) String);

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid(message.into())
}

/// A signature algorithm a token may be signed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Es512,
}

impl Alg {
    const ALL: [(&'static str, Self); 9] = [
        ("RS256", Self::Rs256),
        ("RS384", Self::Rs384),
        ("RS512", Self::Rs512),
        ("PS256", Self::Ps256),
        ("PS384", Self::Ps384),
        ("PS512", Self::Ps512),
        ("ES256", Self::Es256),
        ("ES384", Self::Es384),
        ("ES512", Self::Es512),
    ];

    fn find(name: &str) -> Option<Self> {
        Self::ALL.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
    }

    /// The curve an ECDSA algorithm signs on; `None` for RSA.
    const fn curve(self) -> Option<Curve> {
        match self {
            Self::Es256 => Some(Curve::P256),
            Self::Es384 => Some(Curve::P384),
            Self::Es512 => Some(Curve::P521),
            _ => None,
        }
    }

    fn rsa(self) -> Option<&'static signature::RsaParameters> {
        Some(match self {
            Self::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Self::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Self::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            Self::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
            Self::Ps384 => &signature::RSA_PSS_2048_8192_SHA384,
            Self::Ps512 => &signature::RSA_PSS_2048_8192_SHA512,
            _ => return None,
        })
    }

    /// Whether `key` made `signature` over `message` with this algorithm.
    fn verify(self, key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
        match (key, self.rsa(), self.curve()) {
            (PublicKey::Rsa { n, e }, Some(params), _) => RsaPublicKeyComponents { n, e }
                .verify(params, message, signature)
                .is_ok(),
            (PublicKey::Ec { curve, point }, _, Some(wanted)) if *curve == wanted => {
                let algorithm = match curve {
                    Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED,
                    Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED,
                    Curve::P521 => &signature::ECDSA_P521_SHA512_FIXED,
                };
                UnparsedPublicKey::new(algorithm, point)
                    .verify(message, signature)
                    .is_ok()
            }
            _ => false,
        }
    }
}

/// An elliptic curve a key may be on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    /// The length of a coordinate, in bytes.
    const fn size(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }
}

/// A public key, as the signature library takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PublicKey {
    /// Modulus and exponent, big-endian.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// The uncompressed point: `04`, `x`, `y`.
    Ec { curve: Curve, point: Vec<u8> },
}

/// A key of a provider's key set that can check signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Jwk {
    kid: Option<String>,
    /// The only algorithm it may check, if it says.
    alg: Option<Alg>,
    key: PublicKey,
}

impl Jwk {
    /// Its key id.
    pub(crate) fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Whether it may check a signature made with `alg`.
    fn fits(&self, alg: Alg) -> bool {
        self.alg.is_none_or(|a| a == alg)
            && match &self.key {
                PublicKey::Rsa { .. } => alg.rsa().is_some(),
                PublicKey::Ec { curve, .. } => alg.curve() == Some(*curve),
            }
    }
}

/// The keys of a JSON Web Key Set that can check signatures: public keys for signing,
/// of a kind TeiFS checks. Other keys (encryption keys, symmetric ones, unknown kinds)
/// are skipped, as the specification says; a set that isn't one is refused.
pub(crate) fn key_set(text: &str) -> Result<Vec<Jwk>, String> {
    let json = Json::parse(text).map_err(|e| format!("the key set isn't JSON: {e}"))?;
    let Some(Json::Array(keys)) = json.get("keys") else {
        return Err("the key set has no `keys` list".into());
    };
    Ok(keys.iter().take(MAX_KEYS).filter_map(jwk).collect())
}

/// A key of a key set, if it's one TeiFS can check signatures with.
fn jwk(key: &Json) -> Option<Jwk> {
    let text = |name: &str| key.get(name).and_then(Json::as_str);
    let bytes = |name: &str| text(name).and_then(|t| URL_SAFE_NO_PAD.decode(t).ok());
    if text("use").is_some_and(|u| u != "sig") {
        return None;
    }
    if let Some(ops) = key.get("key_ops") {
        let Json::Array(ops) = ops else { return None };
        if !ops.iter().any(|op| op.as_str() == Some("verify")) {
            return None;
        }
    }
    let alg = match text("alg") {
        Some(name) => Some(Alg::find(name)?),
        None => None,
    };
    let public = match text("kty")? {
        "RSA" => {
            // A private key's members make it no less public, but a key set that
            // publishes one is broken: don't use it.
            if key.get("d").is_some() {
                return None;
            }
            let (n, e) = (bytes("n")?, bytes("e")?);
            // No leading zero bytes, as the specification requires.
            if n.first().is_none_or(|b| *b == 0) || e.first().is_none_or(|b| *b == 0) {
                return None;
            }
            PublicKey::Rsa { n, e }
        }
        "EC" => {
            if key.get("d").is_some() {
                return None;
            }
            let curve = match text("crv")? {
                "P-256" => Curve::P256,
                "P-384" => Curve::P384,
                "P-521" => Curve::P521,
                _ => return None,
            };
            let (x, y) = (bytes("x")?, bytes("y")?);
            if x.len() != curve.size() || y.len() != curve.size() {
                return None;
            }
            let mut point = Vec::with_capacity(1 + 2 * curve.size());
            point.push(4);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            PublicKey::Ec { curve, point }
        }
        _ => return None,
    };
    Some(Jwk {
        kid: text("kid").map(str::to_owned),
        alg,
        key: public,
    })
}

/// A token, read but not yet checked.
#[derive(Debug, Clone)]
pub(crate) struct Token {
    alg: Alg,
    kid: Option<String>,
    /// `header.payload`, as signed.
    signed: String,
    signature: Vec<u8>,
    /// The payload: the claims.
    pub(crate) claims: Json,
}

impl Token {
    /// Reads a token in the JWS compact form (`header.payload.signature`). Its claims
    /// can be looked at (to find its issuer) but mean nothing until [`Self::verify`].
    pub(crate) fn decode(text: &str) -> Result<Self, Invalid> {
        if text.len() > MAX_TOKEN {
            return Err(invalid("The token is too long."));
        }
        let mut parts = text.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid(
                "The token isn't a signed JSON Web Token (header.payload.signature).",
            ));
        };
        let json = |part: &str, what: &str| {
            let bytes = URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| invalid(format!("The token's {what} isn't base64url.")))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| invalid(format!("The token's {what} isn't UTF-8.")))?;
            match Json::parse(text) {
                Ok(json @ Json::Object(_)) => Ok(json),
                Ok(_) => Err(invalid(format!("The token's {what} isn't a JSON object."))),
                Err(e) => Err(invalid(format!("The token's {what} isn't valid JSON: {e}"))),
            }
        };
        let head = json(header, "header")?;
        let alg = match head.get("alg").and_then(Json::as_str) {
            Some(name) => Alg::find(name).ok_or_else(|| {
                invalid(format!(
                    "The token is signed with {name}; only RS256, RS384, RS512, PS256, \
                     PS384, PS512, ES256, ES384 and ES512 are accepted."
                ))
            })?,
            None => return Err(invalid("The token's header names no algorithm.")),
        };
        if head.get("crit").is_some() {
            return Err(invalid(
                "The token's header has critical extensions, which aren't supported.",
            ));
        }
        let kid = match head.get("kid") {
            None => None,
            Some(Json::String(kid)) => Some(kid.clone()),
            Some(_) => return Err(invalid("The token's key id isn't a string.")),
        };
        let claims = json(payload, "payload")?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| invalid("The token's signature isn't base64url."))?;
        Ok(Self {
            alg,
            kid,
            signed: format!("{header}.{payload}"),
            signature,
            claims,
        })
    }

    /// The key id its header names, which the key set should have.
    pub(crate) fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// A string claim.
    pub(crate) fn claim(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(Json::as_str)
    }

    /// Checks the signature with the provider's `keys`: the key its `kid` names, or,
    /// without one, any key that fits its algorithm.
    pub(crate) fn verify(&self, keys: &[Jwk]) -> Result<(), Invalid> {
        let mut candidates = keys
            .iter()
            .filter(|k| self.kid.is_none() || k.kid == self.kid)
            .filter(|k| k.fits(self.alg))
            .peekable();
        if candidates.peek().is_none() {
            return Err(invalid(match &self.kid {
                Some(kid) => format!(
                    "The identity provider has no key {kid} that checks {:?} signatures.",
                    self.alg
                ),
                None => format!(
                    "The identity provider has no key that checks {:?} signatures.",
                    self.alg
                ),
            }));
        }
        if candidates.any(|k| {
            self.alg
                .verify(&k.key, self.signed.as_bytes(), &self.signature)
        }) {
            Ok(())
        } else {
            Err(invalid("The token's signature is not valid."))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! Keys and tokens made here, signed as an identity provider signs them.

    use aws_lc_rs::{
        rand::SystemRandom,
        rsa::KeySize,
        signature::{EcdsaKeyPair, KeyPair as _, RsaKeyPair},
    };

    use super::*;

    /// A signing key of an identity provider, and its public JWK.
    pub(crate) enum Signer {
        Rsa(RsaKeyPair),
        Ec(EcdsaKeyPair, Curve),
    }

    impl Signer {
        pub(crate) fn rsa() -> Self {
            Self::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).unwrap())
        }

        pub(crate) fn ec(curve: Curve) -> Self {
            let algorithm = match curve {
                Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                Curve::P521 => &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
            };
            Self::Ec(EcdsaKeyPair::generate(algorithm).unwrap(), curve)
        }

        /// Its public key as a JWK, with `extra` members (`"alg":"RS256"`).
        pub(crate) fn jwk(&self, kid: &str, extra: &str) -> String {
            let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
            let extra = if extra.is_empty() {
                String::new()
            } else {
                format!(",{extra}")
            };
            match self {
                Self::Rsa(key) => {
                    let public = key.public_key();
                    format!(
                        r#"{{"kty":"RSA","kid":"{kid}","n":"{}","e":"{}"{extra}}}"#,
                        b64(public.modulus().big_endian_without_leading_zero()),
                        b64(public.exponent().big_endian_without_leading_zero())
                    )
                }
                Self::Ec(key, curve) => {
                    let point = key.public_key().as_ref();
                    let size = curve.size();
                    let crv = match curve {
                        Curve::P256 => "P-256",
                        Curve::P384 => "P-384",
                        Curve::P521 => "P-521",
                    };
                    format!(
                        r#"{{"kty":"EC","crv":"{crv}","kid":"{kid}","x":"{}","y":"{}"{extra}}}"#,
                        b64(&point[1..=size]),
                        b64(&point[1 + size..])
                    )
                }
            }
        }

        /// A token with `header` (JSON members besides `alg`) and `claims`, signed with
        /// `alg`.
        pub(crate) fn token(&self, alg: &str, header: &str, claims: &str) -> String {
            let header = if header.is_empty() {
                format!(r#"{{"alg":"{alg}"}}"#)
            } else {
                format!(r#"{{"alg":"{alg}",{header}}}"#)
            };
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(claims)
            );
            let signature = self.sign(alg, signed.as_bytes());
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
        }

        /// Its public key.
        pub(crate) fn public(&self) -> PublicKey {
            match self {
                Self::Rsa(key) => {
                    let public = key.public_key();
                    PublicKey::Rsa {
                        n: public.modulus().big_endian_without_leading_zero().to_vec(),
                        e: public.exponent().big_endian_without_leading_zero().to_vec(),
                    }
                }
                Self::Ec(key, curve) => PublicKey::Ec {
                    curve: *curve,
                    point: key.public_key().as_ref().to_vec(),
                },
            }
        }

        /// `message` signed as JOSE's `alg` signs (ECDSA: with the curve's hash).
        pub(crate) fn sign(&self, alg: &str, message: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            match self {
                Self::Rsa(key) => {
                    let padding: &dyn signature::RsaEncoding = match alg {
                        "RS384" => &signature::RSA_PKCS1_SHA384,
                        "RS512" => &signature::RSA_PKCS1_SHA512,
                        "PS256" => &signature::RSA_PSS_SHA256,
                        "PS384" => &signature::RSA_PSS_SHA384,
                        "PS512" => &signature::RSA_PSS_SHA512,
                        // RS256, or any other name: tokens that lie about it.
                        _ => &signature::RSA_PKCS1_SHA256,
                    };
                    let mut signature = vec![0; key.public_modulus_len()];
                    key.sign(padding, &rng, message, &mut signature).unwrap();
                    signature
                }
                Self::Ec(key, _) => key.sign(&rng, message).unwrap().as_ref().to_vec(),
            }
        }
    }

    fn set(keys: &[String]) -> Vec<Jwk> {
        key_set(&format!(r#"{{"keys":[{}]}}"#, keys.join(","))).unwrap()
    }

    const CLAIMS: &str = r#"{"iss":"https://idp.example.com","sub":"alice"}"#;

    #[test]
    fn every_accepted_algorithm_verifies() {
        let rsa = Signer::rsa();
        let keys = set(&[rsa.jwk("r", "")]);
        for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            let token = Token::decode(&rsa.token(alg, r#""kid":"r""#, CLAIMS)).unwrap();
            assert_eq!(token.verify(&keys), Ok(()), "{alg}");
            assert_eq!(token.claim("sub"), Some("alice"));
        }
        for (curve, alg) in [
            (Curve::P256, "ES256"),
            (Curve::P384, "ES384"),
            (Curve::P521, "ES512"),
        ] {
            let ec = Signer::ec(curve);
            let keys = set(&[ec.jwk("e", "")]);
            let token = Token::decode(&ec.token(alg, "", CLAIMS)).unwrap();
            assert_eq!(token.verify(&keys), Ok(()), "{alg} without a kid");
            // Another curve's algorithm doesn't use this key.
            let wrong = if alg == "ES256" { "ES384" } else { "ES256" };
            let token = Token::decode(&ec.token(wrong, "", CLAIMS)).unwrap();
            assert!(token.verify(&keys).is_err(), "{wrong} on {curve:?}");
        }
    }

    #[test]
    fn only_asymmetric_algorithms_are_accepted() {
        let rsa = Signer::rsa();
        for alg in ["none", "HS256", "HS512", "RS1", "EdDSA", "rs256"] {
            let err = Token::decode(&rsa.token(alg, "", CLAIMS)).unwrap_err();
            assert!(err.0.contains("only RS256"), "{alg}: {err}");
        }
        // An unsigned token, with no signature at all.
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(CLAIMS)
        );
        assert!(Token::decode(&unsigned).is_err());
        let err = Token::decode(&rsa.token("RS256", r#""crit":["b64"]"#, CLAIMS)).unwrap_err();
        assert!(err.0.contains("critical"), "{err}");
    }

    #[test]
    fn signatures_are_checked_with_the_named_fitting_key() {
        let (a, b) = (Signer::rsa(), Signer::rsa());
        let keys = set(&[a.jwk("a", r#""use":"sig","alg":"RS256""#), b.jwk("b", "")]);
        let token = |signer: &Signer, alg, kid: &str| {
            Token::decode(&signer.token(alg, &format!(r#""kid":"{kid}""#), CLAIMS)).unwrap()
        };
        assert_eq!(token(&a, "RS256", "a").verify(&keys), Ok(()));
        assert_eq!(token(&b, "RS256", "b").verify(&keys), Ok(()));
        // Signed by b but naming a: a's key doesn't check it.
        let err = token(&b, "RS256", "a").verify(&keys).unwrap_err();
        assert_eq!(err.0, "The token's signature is not valid.");
        // a is for RS256 only.
        let err = token(&a, "PS256", "a").verify(&keys).unwrap_err();
        assert!(err.0.contains("no key a"), "{err}");
        let err = token(&a, "RS256", "c").verify(&keys).unwrap_err();
        assert!(err.0.contains("no key c"), "{err}");
        // Without a kid, any fitting key may check it.
        let unnamed = Token::decode(&b.token("RS256", "", CLAIMS)).unwrap();
        assert_eq!(unnamed.verify(&keys), Ok(()));
        assert!(unnamed.verify(&[]).is_err());

        // A changed payload no longer verifies.
        let good = a.token("RS256", r#""kid":"a""#, CLAIMS);
        let mut parts: Vec<&str> = good.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(r#"{"iss":"https://idp.example.com","sub":"root"}"#);
        parts[1] = &forged;
        let token = Token::decode(&parts.join(".")).unwrap();
        assert!(token.verify(&keys).is_err());
    }

    #[test]
    fn key_sets_keep_only_signing_keys_they_can_use() {
        let rsa = Signer::rsa();
        let ec = Signer::ec(Curve::P256);
        let keys = set(&[
            rsa.jwk("sig", ""),
            rsa.jwk("enc", r#""use":"enc""#),
            rsa.jwk("ops", r#""key_ops":["encrypt"]"#),
            rsa.jwk("verify", r#""key_ops":["verify"]"#),
            rsa.jwk("unknown-alg", r#""alg":"RSA-OAEP""#),
            rsa.jwk("private", r#""d":"AQAB""#),
            ec.jwk("ec", ""),
            r#"{"kty":"oct","k":"c2VjcmV0","kid":"hmac"}"#.to_owned(),
            r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AA","kid":"short"}"#.to_owned(),
            r#"{"kty":"OKP","crv":"Ed25519","x":"AA","kid":"ed"}"#.to_owned(),
            r#"{"kty":"RSA","n":"AAEC","e":"AQAB","kid":"zero"}"#.to_owned(),
        ]);
        let kids: Vec<_> = keys.iter().filter_map(|k| k.kid.as_deref()).collect();
        assert_eq!(kids, ["sig", "verify", "ec"]);
        for bad in [
            "[]",
            "{}",
            r#"{"keys":{}}"#,
            "not json",
            r#"{"keys":[],"keys":[]}"#,
        ] {
            assert!(key_set(bad).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..150).map(|i| rsa.jwk(&i.to_string(), "")).collect();
        assert_eq!(set(&many).len(), MAX_KEYS);
    }

    #[test]
    fn malformed_tokens_are_refused() {
        let rsa = Signer::rsa();
        let good = rsa.token("RS256", "", CLAIMS);
        let b64 = |text: &str| URL_SAFE_NO_PAD.encode(text);
        let with_header = |header: &str| format!("{}.{}.AA", b64(header), b64(CLAIMS));
        for bad in [
            String::new(),
            "a.b".to_owned(),
            format!("{good}.x"),
            good.replacen('.', "=.", 1),
            with_header("[]"),
            with_header(r#"{"typ":"JWT"}"#),
            with_header(r#"{"alg":"RS256","alg":"none"}"#),
            with_header(r#"{"alg":"RS256","kid":7}"#),
            format!(
                "{}.{}.AA",
                b64(r#"{"alg":"RS256"}"#),
                b64(r#"{"sub":"a","sub":"b"}"#)
            ),
            format!("{}.{}.AA", b64(r#"{"alg":"RS256"}"#), b64("\"text\"")),
            format!("{}.%%%.AA", b64(r#"{"alg":"RS256"}"#)),
            format!(
                "{}.{}.AA",
                b64(r#"{"alg":"RS256"}"#),
                URL_SAFE_NO_PAD.encode([0xff, 0xfe])
            ),
            format!("{good}!"),
            // Well formed and signed, but too long.
            rsa.token(
                "RS256",
                "",
                &format!(r#"{{"sub":"{}"}}"#, "a".repeat(MAX_TOKEN)),
            ),
        ] {
            assert!(Token::decode(&bad).is_err(), "{bad:.60}");
        }
    }
}
