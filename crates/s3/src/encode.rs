//! Listing details: `encoding-type=url` and continuation tokens.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use teidrive_store::After;

/// Percent-encodes a key the way S3 does for `encoding-type=url`: everything but
/// unreserved characters and `/`.
pub(crate) fn url(value: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// A continuation token for where the next page starts.
pub(crate) fn token(after: &After) -> String {
    let (kind, value) = match after {
        After::Key(key) => ('k', key),
        After::Prefix(prefix) => ('p', prefix),
    };
    URL_SAFE_NO_PAD.encode(format!("{kind}{value}"))
}

/// Reads a continuation token back; `None` when it isn't one of ours.
pub(crate) fn parse_token(token: &str) -> Option<After> {
    let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(token).ok()?).ok()?;
    let value = decoded.get(1..)?.to_owned();
    match decoded.as_bytes().first()? {
        b'k' => Some(After::Key(value)),
        b'p' => Some(After::Prefix(value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_encoded_like_s3() {
        assert_eq!(
            url("photos/2026/a b+c%.jpg"),
            "photos/2026/a%20b%2Bc%25.jpg"
        );
        assert_eq!(url("ünï"), "%C3%BCn%C3%AF");
    }

    #[test]
    fn tokens_round_trip() {
        for after in [After::Key("a/b c".into()), After::Prefix("dir/".into())] {
            assert_eq!(parse_token(&token(&after)), Some(after));
        }
        assert_eq!(parse_token("not base64 !"), None);
        assert_eq!(parse_token(&URL_SAFE_NO_PAD.encode("xabc")), None);
    }
}
