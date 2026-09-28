//! Key management: the [`Kms`] trait and [`LocalKms`], a keyring file of named,
//! versioned 256-bit keys. Keep the keyring off the drive it protects: encryption at rest
//! only helps if the key isn't next to the data.

use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Context, CryptoError, DataKey, Result, SealedKey, random, seal, unseal};

/// The key SSE-S3 uses, and SSE-KMS when no key is named (like AWS's `aws/s3`).
pub const DEFAULT_KEY: &str = "teifs-default";

/// A key in a KMS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// Its name.
    pub name: String,
    /// Its newest version, the one that seals new data keys.
    pub version: u32,
    /// When that version was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
}

/// Creates and unseals data keys. Implementations: [`LocalKms`]; remote KMSes (Vault,
/// OpenBao) implement the same trait.
#[async_trait::async_trait]
pub trait Kms: Send + Sync + std::fmt::Debug {
    /// A new data key and its seal under `key` (the default key when `None`).
    async fn generate(&self, key: Option<&str>, context: &Context) -> Result<(DataKey, SealedKey)>;

    /// The data key inside `sealed`, if `context` is the one it was sealed with.
    async fn unseal(&self, sealed: &SealedKey, context: &Context) -> Result<DataKey>;

    /// The keys, by name.
    async fn keys(&self) -> Result<Vec<KeyInfo>>;

    /// Creates a key. Creating one that exists fails.
    async fn create_key(&self, name: &str) -> Result<KeyInfo>;

    /// Adds a new version to a key; older versions keep unsealing what they sealed.
    async fn rotate_key(&self, name: &str) -> Result<KeyInfo>;
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyringFile {
    version: u32,
    keys: BTreeMap<String, Vec<StoredVersion>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredVersion {
    version: u32,
    material: String,
    created_ms: i64,
}

struct KeyVersion {
    version: u32,
    material: Zeroizing<[u8; 32]>,
    created_ms: i64,
}

/// A KMS whose keys live in a keyring file (JSON, readable only by its owner).
pub struct LocalKms {
    path: PathBuf,
    keys: Mutex<BTreeMap<String, Vec<KeyVersion>>>,
}

impl std::fmt::Debug for LocalKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKms")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl LocalKms {
    /// Opens the keyring at `path`, creating it (with the default key) if it's missing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let keys = match fs::read(&path) {
            Ok(bytes) => parse(&bytes)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let keys = BTreeMap::from([(DEFAULT_KEY.to_owned(), vec![new_version(1)])]);
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir).map_err(|e| keyring_error(&e))?;
                }
                write(&path, &keys, true)?;
                keys
            }
            Err(err) => return Err(keyring_error(&err)),
        };
        Ok(Self {
            path,
            keys: Mutex::new(keys),
        })
    }

    /// Where the keyring is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn with_keys<T>(&self, f: impl FnOnce(&mut BTreeMap<String, Vec<KeyVersion>>) -> T) -> T {
        f(&mut self
            .keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}

#[async_trait::async_trait]
impl Kms for LocalKms {
    async fn generate(&self, key: Option<&str>, context: &Context) -> Result<(DataKey, SealedKey)> {
        let name = key.unwrap_or(DEFAULT_KEY);
        self.with_keys(|keys| {
            let newest = keys
                .get(name)
                .and_then(|v| v.last())
                .ok_or_else(|| CryptoError::NoSuchKey(name.to_owned()))?;
            let data_key = DataKey::generate();
            let sealed = seal(&newest.material, context, &data_key, name, newest.version);
            Ok((data_key, sealed))
        })
    }

    async fn unseal(&self, sealed: &SealedKey, context: &Context) -> Result<DataKey> {
        self.with_keys(|keys| {
            let version = keys
                .get(&sealed.kms_key)
                .and_then(|v| v.iter().find(|v| v.version == sealed.kms_version))
                .ok_or_else(|| {
                    CryptoError::NoSuchKey(format!("{} v{}", sealed.kms_key, sealed.kms_version))
                })?;
            unseal(&version.material, context, sealed)
        })
    }

    async fn keys(&self) -> Result<Vec<KeyInfo>> {
        Ok(self.with_keys(|keys| {
            keys.iter()
                .filter_map(|(name, versions)| versions.last().map(|v| info(name, v)))
                .collect()
        }))
    }

    async fn create_key(&self, name: &str) -> Result<KeyInfo> {
        check_name(name)?;
        self.with_keys(|keys| {
            if keys.contains_key(name) {
                return Err(CryptoError::Kms(format!(
                    "a key named {name} already exists"
                )));
            }
            keys.insert(name.to_owned(), vec![new_version(1)]);
            if let Err(err) = write(&self.path, keys, false) {
                keys.remove(name);
                return Err(err);
            }
            Ok(info(name, &keys[name][0]))
        })
    }

    async fn rotate_key(&self, name: &str) -> Result<KeyInfo> {
        self.with_keys(|keys| {
            let versions = keys
                .get_mut(name)
                .ok_or_else(|| CryptoError::NoSuchKey(name.to_owned()))?;
            let next = versions.last().map_or(1, |v| v.version + 1);
            versions.push(new_version(next));
            if let Err(err) = write(&self.path, keys, false) {
                if let Some(versions) = keys.get_mut(name) {
                    versions.pop();
                }
                return Err(err);
            }
            let versions = &keys[name];
            Ok(info(name, &versions[versions.len() - 1]))
        })
    }
}

fn info(name: &str, version: &KeyVersion) -> KeyInfo {
    KeyInfo {
        name: name.to_owned(),
        version: version.version,
        created_ms: version.created_ms,
    }
}

/// Key names: 1 to 64 letters, digits, `-`, `_` and `.`.
fn check_name(name: &str) -> Result<()> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(CryptoError::Kms(
            "a key name is 1 to 64 letters, digits, '-', '_' or '.'".to_owned(),
        ))
    }
}

fn new_version(version: u32) -> KeyVersion {
    let mut material = Zeroizing::new([0u8; 32]);
    random(material.as_mut());
    let created_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    KeyVersion {
        version,
        material,
        created_ms,
    }
}

fn keyring_error(err: &io::Error) -> CryptoError {
    CryptoError::Keyring(err.to_string())
}

fn parse(bytes: &[u8]) -> Result<BTreeMap<String, Vec<KeyVersion>>> {
    let file: KeyringFile =
        serde_json::from_slice(bytes).map_err(|e| CryptoError::Keyring(e.to_string()))?;
    if file.version != 1 {
        return Err(CryptoError::Keyring(format!(
            "keyring version {} is newer than this TeiFS knows",
            file.version
        )));
    }
    let mut keys = BTreeMap::new();
    for (name, stored) in file.keys {
        let mut versions = Vec::with_capacity(stored.len());
        for v in stored {
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(&v.material)
                    .map_err(|e| CryptoError::Keyring(e.to_string()))?,
            );
            let material: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::Keyring(format!("key {name} isn't 256 bits")))?;
            versions.push(KeyVersion {
                version: v.version,
                material: Zeroizing::new(material),
                created_ms: v.created_ms,
            });
        }
        versions.sort_by_key(|v| v.version);
        keys.insert(name, versions);
    }
    Ok(keys)
}

/// Writes the keyring atomically, readable only by its owner.
fn write(path: &Path, keys: &BTreeMap<String, Vec<KeyVersion>>, create_new: bool) -> Result<()> {
    let file = KeyringFile {
        version: 1,
        keys: keys
            .iter()
            .map(|(name, versions)| {
                let stored = versions
                    .iter()
                    .map(|v| StoredVersion {
                        version: v.version,
                        material: STANDARD.encode(v.material.as_ref()),
                        created_ms: v.created_ms,
                    })
                    .collect();
                (name.clone(), stored)
            })
            .collect(),
    };
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&file).expect("the keyring serializes"));
    if create_new && path.exists() {
        return Err(CryptoError::Keyring(format!(
            "{} already exists",
            path.display()
        )));
    }
    // Written whole beside it and renamed, so a crash never leaves half a keyring.
    crate::replace_private(path, &bytes).map_err(|e| keyring_error(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context::object("drive", "bucket", "object")
    }

    #[tokio::test]
    async fn creates_a_private_keyring_with_the_default_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/keyring.json");
        let kms = LocalKms::open(&path).unwrap();
        let keys = kms.keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!((keys[0].name.as_str(), keys[0].version), (DEFAULT_KEY, 1));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn data_keys_unseal_after_reopening_and_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.json");
        let kms = LocalKms::open(&path).unwrap();
        let (key, sealed) = kms.generate(None, &ctx()).await.unwrap();
        assert_eq!(sealed.kms_key, DEFAULT_KEY);

        let rotated = kms.rotate_key(DEFAULT_KEY).await.unwrap();
        assert_eq!(rotated.version, 2);
        let (_, newer) = kms.generate(None, &ctx()).await.unwrap();
        assert_eq!(newer.kms_version, 2);

        drop(kms);
        let kms = LocalKms::open(&path).unwrap();
        assert_eq!(kms.unseal(&sealed, &ctx()).await.unwrap(), key);
        assert!(
            kms.unseal(&sealed, &Context::object("d", "b", "x"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn named_keys() {
        let dir = tempfile::tempdir().unwrap();
        let kms = LocalKms::open(dir.path().join("keyring.json")).unwrap();
        kms.create_key("photos").await.unwrap();
        assert!(kms.create_key("photos").await.is_err());
        assert!(kms.create_key("bad name!").await.is_err());
        let (key, sealed) = kms.generate(Some("photos"), &ctx()).await.unwrap();
        assert_eq!(kms.unseal(&sealed, &ctx()).await.unwrap(), key);
        assert!(matches!(
            kms.generate(Some("missing"), &ctx()).await,
            Err(CryptoError::NoSuchKey(_))
        ));
        assert!(matches!(
            kms.rotate_key("missing").await,
            Err(CryptoError::NoSuchKey(_))
        ));
    }

    #[test]
    fn damaged_keyrings_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.json");
        fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            LocalKms::open(&path),
            Err(CryptoError::Keyring(_))
        ));
        fs::write(&path, br#"{"version":2,"keys":{}}"#).unwrap();
        assert!(matches!(
            LocalKms::open(&path),
            Err(CryptoError::Keyring(_))
        ));
    }
}
