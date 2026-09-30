//! Encryption on transfers, by key prefix as mc names it: `--enc-s3 PREFIX` and
//! `--enc-kms PREFIX=KEY` encrypt what's written there, and `--enc-c PREFIX=FILE` (or
//! `TEIFS_ENC_C`) reads and writes objects there with a customer key (SSE-C).
//!
//! A customer key never comes from the command line, where other users of the machine
//! could see it: `--enc-c` names a file holding it, and `TEIFS_ENC_C` holds
//! `PREFIX=KEY` pairs. The rules are read once per command; each object takes the rule
//! of the longest prefix of its `ALIAS/BUCKET/KEY`.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::Digest;
use zeroize::Zeroizing;

use super::{EncArgs, Error, alias::Aliases};

/// Customer keys for prefixes, as `PREFIX=KEY[,PREFIX=KEY…]` (base64 or hex keys).
pub const ENC_C_ENV: &str = "TEIFS_ENC_C";

/// How an object is encrypted.
#[derive(Debug, PartialEq, Eq)]
pub enum Sse {
    /// SSE-S3.
    S3,
    /// SSE-KMS with this key.
    Kms(String),
    /// SSE-C with this key.
    Customer(CustomerKey),
}

/// A 256-bit customer key, as S3's headers carry it.
#[derive(PartialEq, Eq)]
pub struct CustomerKey {
    base64: Zeroizing<String>,
    md5: String,
}

impl fmt::Debug for CustomerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustomerKey(..)")
    }
}

impl CustomerKey {
    /// A key from 32 bytes, or from text holding them in base64 (padded or not) or hex.
    fn parse(bytes: &[u8]) -> Option<Self> {
        let raw = if bytes.len() == 32 {
            Zeroizing::new(bytes.to_vec())
        } else {
            let text = std::str::from_utf8(bytes).ok()?.trim();
            let decoded = if text.len() == 64 {
                hex_decode(text)?
            } else {
                STANDARD
                    .decode(format!("{text:=<44}"))
                    .ok()
                    .filter(|_| text.len() >= 43)?
            };
            Zeroizing::new(decoded)
        };
        if raw.len() != 32 {
            return None;
        }
        Some(Self {
            base64: Zeroizing::new(STANDARD.encode(&*raw)),
            md5: STANDARD.encode(md5::Md5::digest(&*raw)),
        })
    }

    /// The key, in base64.
    pub fn base64(&self) -> String {
        (*self.base64).clone()
    }

    /// The key's MD5, in base64.
    pub fn md5(&self) -> String {
        self.md5.clone()
    }
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

impl Sse {
    /// `x-amz-server-side-encryption` for a write.
    pub fn mode(sse: Option<&Self>) -> Option<aws_sdk_s3::types::ServerSideEncryption> {
        match sse? {
            Self::S3 => Some(aws_sdk_s3::types::ServerSideEncryption::Aes256),
            Self::Kms(_) => Some(aws_sdk_s3::types::ServerSideEncryption::AwsKms),
            Self::Customer(_) => None,
        }
    }

    /// The KMS key a write names.
    pub fn kms_key(sse: Option<&Self>) -> Option<String> {
        match sse? {
            Self::Kms(key) => Some(key.clone()),
            _ => None,
        }
    }

    /// The customer key reads and writes need.
    pub fn customer(sse: Option<&Self>) -> Option<&CustomerKey> {
        match sse? {
            Self::Customer(key) => Some(key),
            _ => None,
        }
    }
}

/// Sets the SSE-C headers of a request to read or write an object encrypted as
/// `$sse` (an `Option<&Sse>`); none for other objects.
macro_rules! customer_key {
    ($request:expr, $sse:expr) => {{
        let key = $crate::client::sse::Sse::customer($sse);
        $request
            .set_sse_customer_algorithm(key.map(|_| "AES256".to_owned()))
            .set_sse_customer_key(key.map($crate::client::sse::CustomerKey::base64))
            .set_sse_customer_key_md5(key.map($crate::client::sse::CustomerKey::md5))
    }};
}

/// Sets the encryption headers of a request that writes an object as `$sse`.
macro_rules! encrypted {
    ($request:expr, $sse:expr) => {{
        let sse = $sse;
        customer_key!($request, sse)
            .set_server_side_encryption($crate::client::sse::Sse::mode(sse))
            .set_ssekms_key_id($crate::client::sse::Sse::kms_key(sse))
    }};
}

/// Sets the SSE-C headers of a copy whose source is encrypted as `$sse`.
macro_rules! copy_source_key {
    ($request:expr, $sse:expr) => {{
        let key = $crate::client::sse::Sse::customer($sse);
        $request
            .set_copy_source_sse_customer_algorithm(key.map(|_| "AES256".to_owned()))
            .set_copy_source_sse_customer_key(key.map($crate::client::sse::CustomerKey::base64))
            .set_copy_source_sse_customer_key_md5(key.map($crate::client::sse::CustomerKey::md5))
    }};
}

pub(crate) use {copy_source_key, customer_key, encrypted};

/// Prefixes and how objects under them are encrypted.
#[derive(Debug, Default)]
pub struct Rules(Vec<(String, Arc<Sse>)>);

static RULES: OnceLock<Rules> = OnceLock::new();

/// Makes `rules` the command's.
pub fn use_rules(rules: Rules) {
    let _ = RULES.set(rules);
}

/// How the object `name` (`ALIAS/BUCKET/KEY`) is encrypted by the command's rules.
pub fn for_object(name: &str) -> Option<Arc<Sse>> {
    RULES.get()?.find(name)
}

impl Rules {
    /// The rules `args` and `TEIFS_ENC_C` give; each prefix must start with an alias.
    pub fn read(args: &EncArgs, aliases: &Aliases) -> Result<Self, Error> {
        let env = std::env::var(ENC_C_ENV).ok().map(Zeroizing::new);
        Self::from_parts(args, env.as_deref().map(String::as_str), |name| {
            aliases.get(name).is_some()
        })
    }

    fn from_parts(
        args: &EncArgs,
        env: Option<&str>,
        is_alias: impl Fn(&str) -> bool,
    ) -> Result<Self, Error> {
        let mut rules = Self::default();
        for prefix in &args.s3 {
            rules.add(prefix, Sse::S3, &is_alias)?;
        }
        for pair in &args.kms {
            let (prefix, key) = split(pair, "--enc-kms", "KEY")?;
            rules.add(prefix, Sse::Kms(key.to_owned()), &is_alias)?;
        }
        for pair in &args.customer {
            let (prefix, path) = split(pair, "--enc-c", "FILE")?;
            let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| {
                // The path isn't repeated: it may be a key given here by mistake.
                Error::usage(format!("can't read the key file for {prefix}: {e}")).with_hint(
                    format!("--enc-c takes a file holding the key, never the key itself; or set {ENC_C_ENV}"),
                )
            })?);
            let key = CustomerKey::parse(&bytes).ok_or_else(|| {
                Error::usage(format!(
                    "the key file for {prefix} doesn't hold a 256-bit key: 32 bytes, or base64 or hex"
                ))
            })?;
            rules.add(prefix, Sse::Customer(key), &is_alias)?;
        }
        for pair in env
            .into_iter()
            .flat_map(|e| e.split(','))
            .filter(|p| !p.trim().is_empty())
        {
            let (prefix, key) = split(pair.trim(), ENC_C_ENV, "KEY")?;
            let key = CustomerKey::parse(key.as_bytes()).ok_or_else(|| {
                Error::usage(format!(
                    "{ENC_C_ENV}'s key for {prefix} isn't a 256-bit key in base64 or hex"
                ))
            })?;
            rules.add(prefix, Sse::Customer(key), &is_alias)?;
        }
        Ok(rules)
    }

    fn add(
        &mut self,
        prefix: &str,
        sse: Sse,
        is_alias: impl Fn(&str) -> bool,
    ) -> Result<(), Error> {
        let (alias, bucket) = prefix.split_once('/').unwrap_or((prefix, ""));
        if !is_alias(alias) || bucket.is_empty() {
            return Err(Error::usage(format!(
                "`{prefix}` isn't ALIAS/BUCKET[/PREFIX] with a known alias"
            ))
            .with_hint("see `teifs alias ls`"));
        }
        if self.0.iter().any(|(p, _)| p == prefix) {
            return Err(Error::usage(format!(
                "{prefix} is given more than one encryption"
            )));
        }
        self.0.push((prefix.to_owned(), Arc::new(sse)));
        Ok(())
    }

    fn find(&self, name: &str) -> Option<Arc<Sse>> {
        self.0
            .iter()
            .filter(|(prefix, _)| name.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, sse)| Arc::clone(sse))
    }
}

/// `PREFIX=VALUE`, split at the last `=` before the value's base64 padding (prefixes
/// may hold `=`; KMS key names and paths rarely do).
fn split<'a>(pair: &'a str, flag: &str, value: &str) -> Result<(&'a str, &'a str), Error> {
    let at = pair.trim_end_matches('=').rfind('=');
    at.map(|at| (&pair[..at], &pair[at + 1..]))
        .filter(|(p, v)| !p.is_empty() && !v.is_empty())
        .ok_or_else(|| Error::usage(format!("{flag} takes ALIAS/BUCKET[/PREFIX]={value}")))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn args(s3: &[&str], kms: &[&str], c: &[&str]) -> EncArgs {
        let owned = |v: &[&str]| v.iter().map(|&s| s.to_owned()).collect();
        EncArgs {
            s3: owned(s3),
            kms: owned(kms),
            customer: owned(c),
        }
    }

    fn rules(args: &EncArgs, env: Option<&str>) -> Result<Rules, Error> {
        Rules::from_parts(args, env, |alias| alias == "s")
    }

    #[test]
    fn customer_keys_are_raw_base64_or_hex() {
        let b64 = STANDARD.encode(KEY);
        let hex = KEY.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        });
        let raw = CustomerKey::parse(&KEY).unwrap();
        assert_eq!(raw.base64(), b64);
        assert_eq!(raw.md5(), STANDARD.encode(md5::Md5::digest(KEY)));
        for text in [
            b64.clone(),
            format!("{b64}\n"),
            b64.trim_end_matches('=').to_owned(),
            hex,
        ] {
            assert_eq!(CustomerKey::parse(text.as_bytes()).unwrap(), raw, "{text}");
        }
        for bad in [
            &b"short"[..],
            &[7; 31],
            &[7; 33],
            "g".repeat(64).as_bytes(),
            STANDARD.encode([7; 30]).as_bytes(),
        ] {
            assert!(CustomerKey::parse(bad).is_none(), "{bad:?}");
        }
        assert_eq!(format!("{raw:?}"), "CustomerKey(..)");
    }

    #[test]
    fn the_longest_prefix_decides() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("key");
        std::fs::write(&file, KEY).unwrap();
        let c = format!("s/b/secret/={}", file.display());
        let env = format!("s/c={}, ", STANDARD.encode([9; 32]));
        assert!(STANDARD.encode([9; 32]).ends_with('='));
        let got = rules(&args(&["s/b"], &["s/b/d=1/=k"], &[&c]), Some(&env)).unwrap();
        assert_eq!(*got.find("s/b/a").unwrap(), Sse::S3);
        assert_eq!(*got.find("s/b/d=1/x").unwrap(), Sse::Kms("k".into()));
        assert!(matches!(
            *got.find("s/b/secret/x").unwrap(),
            Sse::Customer(_)
        ));
        assert!(matches!(*got.find("s/c/x").unwrap(), Sse::Customer(_)));
        assert!(got.find("s/d/x").is_none());
        let sse = got.find("s/b/d=1/x");
        assert_eq!(Sse::kms_key(sse.as_deref()).as_deref(), Some("k"));
        assert!(Sse::customer(sse.as_deref()).is_none());
    }

    #[test]
    fn mistakes_are_refused_without_showing_keys() {
        let secret = STANDARD.encode(KEY);
        for bad in [
            args(&["x/b"], &[], &[]),
            args(&["s"], &[], &[]),
            args(&["s/b", "s/b"], &[], &[]),
            args(&[], &["s/b"], &[]),
            args(&[], &["s/b="], &[]),
            args(&[], &[], &[&format!("s/b={secret}")]),
        ] {
            let err = rules(&bad, None).unwrap_err().to_string();
            assert!(!err.contains(&secret), "{err}");
        }
        let err = rules(&args(&[], &[], &[]), Some("s/b=nokey")).unwrap_err();
        assert!(err.to_string().contains(ENC_C_ENV), "{err}");
    }
}
