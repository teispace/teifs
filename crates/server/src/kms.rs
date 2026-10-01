//! The server's KMS: a keyring file next to the user's config, or a KMS elsewhere (a
//! Vault or OpenBao transit engine, KES, AWS KMS), with its default key renamed if asked.
//! Secrets (tokens, API keys) come from the environment, never a flag or settings file.

use std::{path::PathBuf, sync::Arc};

use teifs_store::{
    AwsKms, CryptoError, DefaultKeyNamed, KesAuth, KesKms, Kms, LocalKms, TransitKms,
};
use zeroize::Zeroizing;

use crate::ServerError;

/// A Vault or OpenBao transit engine.
#[derive(Debug, Clone)]
pub struct Transit {
    /// Its address, such as `https://vault.example:8200`.
    pub address: String,
    /// Where the engine is mounted (usually `transit`).
    pub mount: String,
    /// A Vault Enterprise or OpenBao namespace.
    pub namespace: Option<String>,
}

/// A KMS outside the drive's machine. Its secrets come from the environment.
#[derive(Debug, Clone)]
pub enum ExternalKms {
    /// A Vault or OpenBao transit engine; its token comes from `VAULT_TOKEN` (or
    /// `BAO_TOKEN`).
    Transit(Transit),
    /// One or more KES servers.
    Kes(Kes),
    /// AWS KMS.
    Aws(AwsKmsConfig),
}

impl ExternalKms {
    /// Which it is, in words.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Transit(transit) => format!("the transit engine at {}", transit.address),
            Self::Kes(kes) => format!("KES at {}", kes.endpoints.join(", ")),
            Self::Aws(aws) => match &aws.region {
                Some(region) => format!("AWS KMS in {region}"),
                None => "AWS KMS".to_owned(),
            },
        }
    }
}

/// KES servers and how TeiFS signs in to them: a certificate and key file, else the API
/// key in `TEIFS_KMS_KES_API_KEY` (or MinIO's `MINIO_KMS_KES_API_KEY`).
#[derive(Debug, Clone)]
pub struct Kes {
    /// The servers, such as `https://kes.example:7373`.
    pub endpoints: Vec<String>,
    /// A client certificate (PEM) and its key, instead of an API key.
    pub client_cert: Option<(PathBuf, PathBuf)>,
    /// The certificates KES's are checked against, else the system's.
    pub ca: Option<PathBuf>,
}

/// AWS KMS: credentials, and the region unless given, come from AWS's usual places.
#[derive(Debug, Clone, Default)]
pub struct AwsKmsConfig {
    /// The region.
    pub region: Option<String>,
    /// Another endpoint, such as `LocalStack`'s or a VPC endpoint.
    pub endpoint: Option<String>,
}

/// Where a server's KMS keys are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsLocation {
    /// A keyring file; `created` when this start made it (a new key: back it up).
    Keyring {
        /// The file.
        path: PathBuf,
        /// Whether this start created it.
        created: bool,
    },
    /// A transit engine.
    Transit(String),
    /// KES servers, and TeiFS's identity there.
    Kes {
        /// The servers.
        endpoints: Vec<String>,
        /// The identity KES's policy names.
        identity: String,
    },
    /// AWS KMS in a region.
    AwsKms(String),
}

impl KmsLocation {
    /// Where it is, in words.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Keyring { path, .. } => path.display().to_string(),
            Self::Transit(address) => format!("the transit engine at {address}"),
            Self::Kes {
                endpoints,
                identity,
            } => {
                format!("KES at {} (identity {identity})", endpoints.join(", "))
            }
            Self::AwsKms(region) => format!("AWS KMS in {region}"),
        }
    }
}

/// The KMS: an external one when one is given, else the keyring (the drive's default one
/// unless `keyring` names another), its default key renamed to `default_key` if given.
///
/// # Errors
///
/// When the KMS can't be opened or its secrets aren't in the environment.
pub async fn open_kms(
    external: Option<&ExternalKms>,
    keyring: Option<PathBuf>,
    drive: &str,
    default_key: Option<String>,
) -> Result<(Arc<dyn Kms>, KmsLocation), ServerError> {
    let (kms, location) = if let Some(external) = external {
        open_external(external).await?
    } else {
        let path = match keyring {
            Some(path) => path,
            None => default_keyring(drive)?,
        };
        let created = !path.exists();
        let kms = LocalKms::open(&path).map_err(|source| ServerError::Keyring {
            path: path.clone(),
            source,
        })?;
        (
            Arc::new(kms) as Arc<dyn Kms>,
            KmsLocation::Keyring { path, created },
        )
    };
    Ok((with_default_key(kms, default_key), location))
}

/// `kms`, its default key renamed to `name` if one is given.
#[must_use]
pub fn with_default_key(kms: Arc<dyn Kms>, name: Option<String>) -> Arc<dyn Kms> {
    match name {
        Some(name) => Arc::new(DefaultKeyNamed::new(kms, name)),
        None => kms,
    }
}

/// Opens a KMS outside the drive's machine; it and where it is.
///
/// # Errors
///
/// When its secrets aren't in the environment, a file it needs can't be read, or it
/// can't be set up.
pub async fn open_external(
    external: &ExternalKms,
) -> Result<(Arc<dyn Kms>, KmsLocation), ServerError> {
    match external {
        ExternalKms::Transit(transit) => {
            let token = env("VAULT_TOKEN")
                .or_else(|| env("BAO_TOKEN"))
                .ok_or_else(|| ServerError::NoTransitToken(transit.address.clone()))?;
            let location = KmsLocation::Transit(transit.address.clone());
            let kms = TransitKms::new(
                &transit.address,
                &transit.mount,
                token.to_string(),
                transit.namespace.clone(),
            )
            .map_err(|source| failed(&location, source))?;
            Ok((Arc::new(kms), location))
        }
        ExternalKms::Kes(kes) => {
            let words = external.describe();
            let read = |path: &PathBuf| {
                std::fs::read(path).map_err(|e| ServerError::Kms {
                    kms: words.clone(),
                    source: CryptoError::Kms(format!("can't read {}: {e}", path.display())),
                })
            };
            let auth = match &kes.client_cert {
                Some((cert, key)) => KesAuth::Certificate {
                    chain: read(cert)?,
                    key: Zeroizing::new(read(key)?),
                },
                None => KesAuth::ApiKey(
                    env("TEIFS_KMS_KES_API_KEY")
                        .or_else(|| env("MINIO_KMS_KES_API_KEY"))
                        .ok_or_else(|| ServerError::NoKesIdentity(kes.endpoints.join(", ")))?,
                ),
            };
            let ca = kes.ca.as_ref().map(read).transpose()?;
            let endpoints: Vec<&str> = kes.endpoints.iter().map(String::as_str).collect();
            let kms = KesKms::new(&endpoints, auth, ca.as_deref()).map_err(|source| {
                ServerError::Kms {
                    kms: words.clone(),
                    source,
                }
            })?;
            let location = KmsLocation::Kes {
                endpoints: kes.endpoints.clone(),
                identity: kms.identity().to_owned(),
            };
            Ok((Arc::new(kms), location))
        }
        ExternalKms::Aws(aws) => {
            let kms = AwsKms::from_environment(aws.region.clone(), aws.endpoint.clone())
                .await
                .map_err(|source| ServerError::Kms {
                    kms: "AWS KMS".to_owned(),
                    source,
                })?;
            let location = KmsLocation::AwsKms(kms.region().to_owned());
            Ok((Arc::new(kms), location))
        }
    }
}

/// A secret from the environment, if it's set and not empty.
fn env(name: &str) -> Option<Zeroizing<String>> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .map(Zeroizing::new)
}

fn failed(location: &KmsLocation, source: CryptoError) -> ServerError {
    ServerError::Kms {
        kms: location.describe(),
        source,
    }
}

/// Where a drive's keyring goes by default: the user's config folder, not the drive.
///
/// # Errors
///
/// When the user has no config folder.
pub fn default_keyring(drive: &str) -> Result<PathBuf, ServerError> {
    let dir = dirs::config_dir().ok_or(ServerError::NoKeyringHome)?;
    Ok(dir.join("teifs").join("keys").join(format!("{drive}.json")))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use teifs_crypto::Context;
    use teifs_store::DEFAULT_KEY;

    use super::*;

    fn kes(client_cert: Option<(PathBuf, PathBuf)>) -> ExternalKms {
        ExternalKms::Kes(Kes {
            endpoints: vec!["https://kes1:7373".into(), "https://kes2:7373".into()],
            client_cert,
            ca: None,
        })
    }

    #[test]
    fn kmses_are_described() {
        let transit = ExternalKms::Transit(Transit {
            address: "https://vault:8200".into(),
            mount: "transit".into(),
            namespace: None,
        });
        assert_eq!(
            transit.describe(),
            "the transit engine at https://vault:8200"
        );
        assert_eq!(
            kes(None).describe(),
            "KES at https://kes1:7373, https://kes2:7373"
        );
        let aws = |region: Option<&str>| {
            ExternalKms::Aws(AwsKmsConfig {
                region: region.map(str::to_owned),
                endpoint: None,
            })
            .describe()
        };
        assert_eq!(aws(Some("eu-west-1")), "AWS KMS in eu-west-1");
        assert_eq!(aws(None), "AWS KMS");
        let location = KmsLocation::Kes {
            endpoints: vec!["https://kes:7373".into()],
            identity: "ea98".into(),
        };
        assert_eq!(
            location.describe(),
            "KES at https://kes:7373 (identity ea98)"
        );
        assert_eq!(
            KmsLocation::AwsKms("us-east-1".into()).describe(),
            "AWS KMS in us-east-1"
        );
    }

    #[tokio::test]
    async fn kes_needs_a_way_to_sign_in() {
        if env("TEIFS_KMS_KES_API_KEY").is_some() || env("MINIO_KMS_KES_API_KEY").is_some() {
            eprintln!("skipped: a KES API key is set");
            return;
        }
        let err = open_external(&kes(None)).await.unwrap_err();
        assert!(
            matches!(&err, ServerError::NoKesIdentity(e) if e == "https://kes1:7373, https://kes2:7373")
        );
        assert!(err.to_string().contains("TEIFS_KMS_KES_API_KEY"), "{err}");
    }

    #[tokio::test]
    async fn unreadable_certificates_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("client.pem");
        let err = open_external(&kes(Some((missing.clone(), missing.clone()))))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.starts_with("can't use KES at https://kes1:7373"),
            "{text}"
        );
        assert!(
            text.contains(&format!("can't read {}", missing.display())),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_default_key_can_be_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = dir.path().join("keyring.json");
        let (kms, location) = open_kms(None, Some(keyring.clone()), "drive", None)
            .await
            .unwrap();
        assert_eq!(
            location,
            KmsLocation::Keyring {
                path: keyring.clone(),
                created: true
            }
        );
        kms.create_key("shared").await.unwrap();
        let context = Context::object("drive", "bucket", "object");
        let (_, sealed) = kms.generate(None, &context).await.unwrap();
        assert_eq!(sealed.kms_key, DEFAULT_KEY);
        let (kms, location) = open_kms(None, Some(keyring.clone()), "drive", Some("shared".into()))
            .await
            .unwrap();
        assert_eq!(
            location,
            KmsLocation::Keyring {
                path: keyring,
                created: false
            }
        );
        let (_, sealed) = kms.generate(None, &context).await.unwrap();
        assert_eq!(sealed.kms_key, "shared");
    }
}
