//! Which KMS seals a drive's keys when it isn't the keyring: a Vault or OpenBao transit
//! engine, KES, or AWS KMS. `teifs serve` and the key commands share these settings.
//! Secrets never come from flags: the transit token from `VAULT_TOKEN` (or `BAO_TOKEN`),
//! KES's API key from `TEIFS_KMS_KES_API_KEY`, AWS's credentials from AWS's usual places.
//!
//! MinIO's `MINIO_KMS_KES_*` variables work as well when no TeiFS KMS setting is given,
//! so a MinIO deployment's environment carries over.

use std::path::{Path, PathBuf};

use teifs_server::{AwsKmsConfig, ExternalKms, Kes, Transit};

/// The KMS settings.
#[derive(clap::Args, Clone, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "each field is a flag, named as clap names it"
)]
pub(crate) struct KmsArgs {
    /// Use a Vault or OpenBao transit engine as the KMS (e.g. `https://vault:8200`);
    /// its token comes from `VAULT_TOKEN` or `BAO_TOKEN`.
    #[arg(
        long,
        env = "TEIFS_KMS_TRANSIT",
        conflicts_with_all = ["kms_keyring", "kms_kes", "kms_aws"]
    )]
    pub kms_transit: Option<String>,
    /// Where the transit engine is mounted.
    #[arg(long, default_value = "transit", env = "TEIFS_KMS_TRANSIT_MOUNT")]
    pub kms_transit_mount: String,
    /// The transit engine's namespace (Vault Enterprise, OpenBao).
    #[arg(long, env = "TEIFS_KMS_TRANSIT_NAMESPACE")]
    pub kms_transit_namespace: Option<String>,
    /// Use KES as the KMS: one or more servers, comma-separated (e.g.
    /// `https://kes:7373`). TeiFS signs in with the API key in `TEIFS_KMS_KES_API_KEY`,
    /// or with --kms-kes-cert and --kms-kes-key.
    #[arg(
        long,
        env = "TEIFS_KMS_KES",
        value_delimiter = ',',
        conflicts_with_all = ["kms_keyring", "kms_aws"]
    )]
    pub kms_kes: Vec<String>,
    /// A client certificate (PEM) to sign in to KES with, instead of an API key.
    #[arg(long, env = "TEIFS_KMS_KES_CERT", requires = "kms_kes_key")]
    pub kms_kes_cert: Option<PathBuf>,
    /// The client certificate's private key (PEM).
    #[arg(long, env = "TEIFS_KMS_KES_KEY", requires = "kms_kes_cert")]
    pub kms_kes_key: Option<PathBuf>,
    /// The certificate authorities KES's certificate is checked against (PEM; default:
    /// the system's).
    #[arg(long, env = "TEIFS_KMS_KES_CA")]
    pub kms_kes_ca: Option<PathBuf>,
    /// Use AWS KMS: credentials come from AWS's usual places (environment, shared
    /// config and SSO, instance and container roles).
    #[arg(long, env = "TEIFS_KMS_AWS", conflicts_with = "kms_keyring")]
    pub kms_aws: bool,
    /// AWS KMS's region (default: AWS's configuration's).
    #[arg(long, env = "TEIFS_KMS_AWS_REGION", requires = "kms_aws")]
    pub kms_aws_region: Option<String>,
    /// Another AWS KMS endpoint, such as a VPC endpoint or a local emulator.
    #[arg(long, env = "TEIFS_KMS_AWS_ENDPOINT", requires = "kms_aws")]
    pub kms_aws_endpoint: Option<String>,
    /// The key to use where TeiFS would use `teifs-default`: SSE-S3, SSE-KMS without a
    /// key, and the drive's own secrets. Keys sealed before keep opening.
    #[arg(long, env = "TEIFS_KMS_DEFAULT_KEY")]
    pub kms_default_key: Option<String>,
}

impl KmsArgs {
    /// The external KMS these settings name, if any. With none named and no `keyring`,
    /// MinIO's `MINIO_KMS_KES_ENDPOINT` and its companions name one.
    pub(crate) fn external(&self, keyring: Option<&Path>) -> Option<ExternalKms> {
        self.external_with(keyring, &|name| {
            std::env::var(name).ok().filter(|v| !v.trim().is_empty())
        })
    }

    /// The default key's name, if it's renamed: the setting, else MinIO's
    /// `MINIO_KMS_KES_KEY_NAME` when KES came from MinIO's variables.
    pub(crate) fn default_key(&self, keyring: Option<&Path>) -> Option<String> {
        self.default_key_with(keyring, &|name| {
            std::env::var(name).ok().filter(|v| !v.trim().is_empty())
        })
    }

    fn external_with(
        &self,
        keyring: Option<&Path>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Option<ExternalKms> {
        if let Some(address) = &self.kms_transit {
            return Some(ExternalKms::Transit(Transit {
                address: address.clone(),
                mount: self.kms_transit_mount.clone(),
                namespace: self.kms_transit_namespace.clone(),
            }));
        }
        if self.kms_aws {
            return Some(ExternalKms::Aws(AwsKmsConfig {
                region: self.kms_aws_region.clone(),
                endpoint: self.kms_aws_endpoint.clone(),
            }));
        }
        let endpoints = endpoints(&self.kms_kes);
        if !endpoints.is_empty() {
            return Some(ExternalKms::Kes(Kes {
                endpoints,
                client_cert: self.kms_kes_cert.clone().zip(self.kms_kes_key.clone()),
                ca: self.kms_kes_ca.clone(),
            }));
        }
        if keyring.is_some() {
            return None;
        }
        let endpoints = endpoints_from(&env("MINIO_KMS_KES_ENDPOINT")?);
        (!endpoints.is_empty()).then(|| {
            let file = |name| env(name).map(PathBuf::from);
            ExternalKms::Kes(Kes {
                endpoints,
                client_cert: file("MINIO_KMS_KES_CERT_FILE").zip(file("MINIO_KMS_KES_KEY_FILE")),
                ca: file("MINIO_KMS_KES_CAPATH"),
            })
        })
    }

    fn default_key_with(
        &self,
        keyring: Option<&Path>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Option<String> {
        if self.kms_default_key.is_some() {
            return self.kms_default_key.clone();
        }
        let from_minio = endpoints(&self.kms_kes).is_empty()
            && self.kms_transit.is_none()
            && !self.kms_aws
            && keyring.is_none()
            && env("MINIO_KMS_KES_ENDPOINT").is_some();
        from_minio.then(|| env("MINIO_KMS_KES_KEY_NAME")).flatten()
    }
}

/// The endpoints given, without blanks.
fn endpoints(given: &[String]) -> Vec<String> {
    given
        .iter()
        .map(|e| e.trim())
        .filter(|e| !e.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A comma-separated list of endpoints.
fn endpoints_from(list: &str) -> Vec<String> {
    endpoints(&list.split(',').map(str::to_owned).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const MINIO: [(&str, &str); 5] = [
        (
            "MINIO_KMS_KES_ENDPOINT",
            "https://kes1:7373, https://kes2:7373,",
        ),
        ("MINIO_KMS_KES_CERT_FILE", "/certs/client.crt"),
        ("MINIO_KMS_KES_KEY_FILE", "/certs/client.key"),
        ("MINIO_KMS_KES_CAPATH", "/certs/ca.pem"),
        ("MINIO_KMS_KES_KEY_NAME", "minio-default"),
    ];

    fn kes(kms: Option<ExternalKms>) -> Kes {
        match kms {
            Some(ExternalKms::Kes(kes)) => kes,
            other => panic!("not KES: {other:?}"),
        }
    }

    #[test]
    fn no_setting_is_the_keyring() {
        let args = KmsArgs::default();
        assert!(args.external_with(None, &env(&[])).is_none());
        assert_eq!(args.default_key_with(None, &env(&[])), None);
    }

    #[test]
    fn each_kms_is_named_by_its_settings() {
        let transit = KmsArgs {
            kms_transit: Some("https://vault:8200".into()),
            kms_transit_mount: "secrets".into(),
            kms_transit_namespace: Some("team".into()),
            ..KmsArgs::default()
        };
        let Some(ExternalKms::Transit(t)) = transit.external_with(None, &env(&MINIO)) else {
            panic!("transit")
        };
        assert_eq!(
            (t.address.as_str(), t.mount.as_str(), t.namespace.as_deref()),
            ("https://vault:8200", "secrets", Some("team"))
        );
        let aws = KmsArgs {
            kms_aws: true,
            kms_aws_region: Some("eu-west-1".into()),
            kms_aws_endpoint: Some("http://127.0.0.1:5000".into()),
            ..KmsArgs::default()
        };
        let Some(ExternalKms::Aws(a)) = aws.external_with(None, &env(&MINIO)) else {
            panic!("aws")
        };
        assert_eq!(
            (a.region.as_deref(), a.endpoint.as_deref()),
            (Some("eu-west-1"), Some("http://127.0.0.1:5000"))
        );
        let given = KmsArgs {
            kms_kes: vec!["https://kes:7373".into(), " ".into()],
            kms_kes_cert: Some("c.pem".into()),
            kms_kes_key: Some("k.pem".into()),
            kms_kes_ca: Some("ca.pem".into()),
            ..KmsArgs::default()
        };
        let k = kes(given.external_with(None, &env(&MINIO)));
        assert_eq!(k.endpoints, ["https://kes:7373"]);
        assert_eq!(
            k.client_cert,
            Some((PathBuf::from("c.pem"), PathBuf::from("k.pem")))
        );
        assert_eq!(k.ca, Some(PathBuf::from("ca.pem")));
        // MinIO's key name only applies when MinIO's variables chose KES.
        assert_eq!(given.default_key_with(None, &env(&MINIO)), None);
    }

    #[test]
    fn minios_kes_variables_carry_over() {
        let args = KmsArgs::default();
        let k = kes(args.external_with(None, &env(&MINIO)));
        assert_eq!(k.endpoints, ["https://kes1:7373", "https://kes2:7373"]);
        assert_eq!(
            k.client_cert,
            Some((
                PathBuf::from("/certs/client.crt"),
                PathBuf::from("/certs/client.key")
            ))
        );
        assert_eq!(k.ca, Some(PathBuf::from("/certs/ca.pem")));
        assert_eq!(
            args.default_key_with(None, &env(&MINIO)).as_deref(),
            Some("minio-default")
        );
        // An API key instead of a certificate.
        let k = kes(args.external_with(None, &env(&MINIO[..1])));
        assert_eq!((k.client_cert, k.ca), (None, None));
        // A setting of TeiFS's own wins.
        let keyring = Path::new("keyring.json");
        assert!(args.external_with(Some(keyring), &env(&MINIO)).is_none());
        assert_eq!(args.default_key_with(Some(keyring), &env(&MINIO)), None);
        let named = KmsArgs {
            kms_default_key: Some("mine".into()),
            ..KmsArgs::default()
        };
        assert_eq!(
            named.default_key_with(None, &env(&MINIO)).as_deref(),
            Some("mine")
        );
        assert!(
            args.external_with(None, &env(&[("MINIO_KMS_KES_ENDPOINT", " , ")]))
                .is_none()
        );
    }
}
