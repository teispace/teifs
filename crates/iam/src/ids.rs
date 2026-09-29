//! Random identifiers shaped like AWS's.

use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

/// AWS's unique-id alphabet (base32: no 0, 1, 8, 9).
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The kinds of unique id, by AWS's prefixes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    User,
    Group,
    Policy,
    Role,
}

/// A new unique id: the kind's prefix and 17 random base32 characters (21 in all).
pub(crate) fn unique(kind: Kind) -> String {
    let prefix = match kind {
        Kind::User => "AIDA",
        Kind::Group => "AGPA",
        Kind::Policy => "ANPA",
        Kind::Role => "AROA",
    };
    format!("{prefix}{}", base32(17))
}

/// A new access key id: `TKIA` and 16 base32 characters, 20 in all like AWS's `AKIA…`
/// ones but not mistaken for them by secret scanners.
pub(crate) fn access_key() -> String {
    format!("TKIA{}", base32(16))
}

/// A new temporary access key id: `TSIA` and 16 base32 characters (AWS's are `ASIA…`).
pub(crate) fn session_key() -> String {
    format!("{}{}", crate::sessions::PREFIX, base32(16))
}

/// A new secret key: 240 random bits as 40 base64 characters, like AWS's.
pub(crate) fn secret_key() -> Zeroizing<String> {
    let salt = Zeroizing::new(teifs_crypto::random_salt());
    Zeroizing::new(STANDARD.encode(&salt[..30]))
}

/// A new 12-digit account id that doesn't start with 0.
pub(crate) fn account() -> String {
    let mut digits = String::with_capacity(12);
    while digits.len() < 12 {
        for byte in teifs_crypto::random_salt() {
            // 250 is a multiple of 10: rejecting 250–255 keeps every digit equally likely.
            if byte < 250 && digits.len() < 12 && !(digits.is_empty() && byte % 10 == 0) {
                digits.push(char::from(b'0' + byte % 10));
            }
        }
    }
    digits
}

fn base32(len: usize) -> String {
    teifs_crypto::random_salt()[..len]
        .iter()
        .map(|b| char::from(BASE32[usize::from(b % 32)]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let id = unique(Kind::User);
        assert_eq!(id.len(), 21);
        assert!(id.starts_with("AIDA"));
        assert!(id.bytes().all(|b| BASE32.contains(&b)));
        assert!(unique(Kind::Group).starts_with("AGPA"));
        assert!(unique(Kind::Policy).starts_with("ANPA"));
        assert!(unique(Kind::Role).starts_with("AROA"));
        let key = access_key();
        assert_eq!(key.len(), 20);
        assert!(key.starts_with("TKIA"));
        let session = session_key();
        assert!(crate::sessions::is_session_key(&session), "{session}");
        assert!(!crate::sessions::is_session_key(&key));
        let secret = secret_key();
        assert_eq!(secret.len(), 40);
        assert_ne!(*secret, *secret_key());
        for _ in 0..100 {
            let account = account();
            assert_eq!(account.len(), 12);
            assert!(account.bytes().all(|b| b.is_ascii_digit()));
            assert!(!account.starts_with('0'));
        }
    }
}
