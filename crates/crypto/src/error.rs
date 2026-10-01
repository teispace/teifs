/// Why an encryption operation failed.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Authentication failed: the wrong key or context, or data that was changed,
    /// reordered or cut short.
    #[error("the data or key is wrong or has been tampered with")]
    Authentication,
    /// An SSE-C key isn't a base64 256-bit key, or its MD5 doesn't match.
    #[error("invalid customer key: {0}")]
    InvalidCustomerKey(&'static str),
    /// The customer key isn't the one the object was encrypted with.
    #[error("the customer key doesn't match the object's key")]
    WrongCustomerKey,
    /// The KMS has no key by that name.
    #[error("the KMS has no key named {0}")]
    NoSuchKey(String),
    /// A key by that name exists already.
    #[error("a key named {0} already exists")]
    KeyExists(String),
    /// A key's name isn't one TeiFS takes.
    #[error("a key name is 1 to 64 letters, digits, '-', '_' or '.'")]
    InvalidKeyName,
    /// A sealed key's format version is unknown.
    #[error("unknown sealed key version {0}")]
    UnknownVersion(u8),
    /// The KMS's keyring couldn't be read or written.
    #[error("the KMS keyring: {0}")]
    Keyring(String),
    /// The KMS failed or refused; the message names the KMS.
    #[error("{0}")]
    Kms(String),
}
