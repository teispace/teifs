//! Replication targets: other S3 services' buckets a bucket replicates to, kept in the
//! drive's settings with their secret keys sealed by a key of their own, which the KMS
//! seals in turn (as IAM's keys are).

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use teifs_crypto::{Context, DEFAULT_KEY, DataKey, SealedKey};
use teifs_types::replication::{RemoteTarget, TARGET_ARN};
use zeroize::Zeroizing;

use crate::{Store, StoreError, error::Result, now_ms};

/// The setting the targets are kept in.
const TARGETS: &str = "replication.targets";

/// The setting the key sealing their secrets is kept in, sealed by the KMS.
const KEY: &str = "replication.key";

/// A target as kept: what anyone may see, and its secrets, sealed.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kept {
    target: RemoteTarget,
    /// The secret key, sealed to the target's ARN (base64).
    secret: String,
    /// A session's token, if the key is temporary, sealed the same way (base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
}

/// The secrets requests to a target are signed with.
pub struct TargetSecrets {
    /// The secret key.
    pub secret_key: Zeroizing<String>,
    /// A session's token, for temporary credentials.
    pub session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for TargetSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetSecrets").finish_non_exhaustive()
    }
}

/// A target to add: where it is, and the secrets that sign there.
pub struct NewTarget {
    /// The target to change, when it's an edit of one (its other fields replace the
    /// target's).
    pub arn: Option<String>,
    /// The bucket on this drive that replicates to it.
    pub source_bucket: String,
    /// The service's host and port.
    pub endpoint: String,
    /// Whether it's reached over HTTPS.
    pub secure: bool,
    /// The bucket there.
    pub target_bucket: String,
    /// Its region.
    pub region: String,
    /// The access key.
    pub access_key: String,
    /// The secrets (`None` keeps the target's, when it's an edit).
    pub secrets: Option<TargetSecrets>,
    /// The storage class replicas get there.
    pub storage_class: String,
    /// The most bytes a second it's sent (0: no limit).
    pub bandwidth_limit: u64,
    /// Whether writes wait for the replica.
    pub sync: bool,
    /// How often it's checked, in seconds.
    pub health_check_secs: u64,
}

impl std::fmt::Debug for NewTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewTarget")
            .field("source_bucket", &self.source_bucket)
            .field("endpoint", &self.endpoint)
            .field("target_bucket", &self.target_bucket)
            .finish_non_exhaustive()
    }
}

fn read(json: Option<&str>) -> Result<Vec<Kept>> {
    json.map_or_else(
        || Ok(Vec::new()),
        |json| serde_json::from_str(json).map_err(|_| StoreError::CorruptMetadata),
    )
}

fn seal(key: &DataKey, arn: &str, secret: &str) -> String {
    STANDARD.encode(key.seal_secret(arn.as_bytes(), secret.as_bytes()))
}

fn open(key: &DataKey, arn: &str, sealed: &str) -> Result<Zeroizing<String>> {
    let sealed = STANDARD
        .decode(sealed)
        .map_err(|_| StoreError::CorruptMetadata)?;
    let plain = key.open_secret(arn.as_bytes(), &sealed)?;
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| StoreError::CorruptMetadata)
}

impl Store {
    /// The key that seals targets' secrets, made (and sealed by the KMS) on first use.
    async fn targets_key(&self) -> Result<DataKey> {
        if let Some(key) = self.inner.targets_key.get() {
            return Ok(key.clone());
        }
        let kms = self.kms().ok_or(StoreError::NoKms)?;
        let context = Context::replication(&self.format().drive);
        let kept = self
            .blocking(|inner| Ok(inner.system().setting(KEY)?))
            .await?;
        let key = if let Some(sealed) = kept {
            let sealed: SealedKey =
                serde_json::from_str(&sealed).map_err(|_| StoreError::CorruptMetadata)?;
            kms.unseal(&sealed, &context).await?
        } else {
            let (key, sealed) = kms.generate(Some(DEFAULT_KEY), &context).await?;
            let sealed = serde_json::to_string(&sealed).map_err(|_| StoreError::CorruptMetadata)?;
            // Another caller may have made one meanwhile: the first kept wins.
            let winner = self
                .blocking(move |inner| {
                    let system = inner.system();
                    if let Some(kept) = system.setting(KEY)? {
                        return Ok(Some(kept));
                    }
                    system.set_setting(KEY, Some(&sealed))?;
                    Ok(None)
                })
                .await?;
            match winner {
                Some(kept) => {
                    let sealed: SealedKey =
                        serde_json::from_str(&kept).map_err(|_| StoreError::CorruptMetadata)?;
                    kms.unseal(&sealed, &context).await?
                }
                None => key,
            }
        };
        let _ = self.inner.targets_key.set(key.clone());
        Ok(key)
    }

    /// The replication targets, of `bucket` alone when given, without their secrets.
    pub async fn replication_targets(&self, bucket: Option<&str>) -> Result<Vec<RemoteTarget>> {
        let bucket = bucket.map(str::to_owned);
        self.blocking(move |inner| {
            if let Some(bucket) = &bucket {
                inner.bucket(bucket)?;
            }
            let kept = read(inner.system().setting(TARGETS)?.as_deref())?;
            Ok(kept
                .into_iter()
                .map(|k| k.target)
                .filter(|t| bucket.as_ref().is_none_or(|b| *b == t.source_bucket))
                .collect())
        })
        .await
    }

    /// The target `arn` names, if there is one.
    pub async fn replication_target(&self, arn: &str) -> Result<Option<RemoteTarget>> {
        Ok(self
            .replication_targets(None)
            .await?
            .into_iter()
            .find(|t| t.arn == arn))
    }

    /// The secrets that sign requests to the target `arn` names.
    pub async fn replication_target_secrets(&self, arn: &str) -> Result<TargetSecrets> {
        let key = self.targets_key().await?;
        let arn = arn.to_owned();
        self.blocking(move |inner| {
            let kept = read(inner.system().setting(TARGETS)?.as_deref())?;
            let found = kept
                .iter()
                .find(|k| k.target.arn == arn)
                .ok_or(StoreError::InvalidRequest("no such replication target"))?;
            Ok(TargetSecrets {
                secret_key: open(&key, &arn, &found.secret)?,
                session_token: found
                    .session_token
                    .as_deref()
                    .map(|token| open(&key, &arn, token))
                    .transpose()?,
            })
        })
        .await
    }

    /// Adds a target for `new.source_bucket`, or changes the one `new.arn` names,
    /// answering its ARN. Adding a target of the same bucket at the same place and bucket
    /// changes that one, which keeps its ARN.
    pub async fn add_replication_target(&self, new: NewTarget) -> Result<String> {
        let key = self.targets_key().await?;
        let id = uuid::Uuid::new_v4().to_string();
        self.blocking(move |inner| {
            inner.bucket(&new.source_bucket)?;
            let system = inner.system();
            let mut kept = read(system.setting(TARGETS)?.as_deref())?;
            let same = |t: &RemoteTarget| {
                t.source_bucket == new.source_bucket
                    && t.endpoint == new.endpoint
                    && t.target_bucket == new.target_bucket
            };
            let found = match &new.arn {
                Some(arn) => Some(
                    kept.iter()
                        .position(|k| {
                            k.target.arn == *arn && k.target.source_bucket == new.source_bucket
                        })
                        .ok_or(StoreError::InvalidRequest("no such replication target"))?,
                ),
                None => kept.iter().position(|k| same(&k.target)),
            };
            // Another target can't be made to point where one already does.
            if kept
                .iter()
                .enumerate()
                .any(|(i, k)| Some(i) != found && same(&k.target))
            {
                return Err(StoreError::InvalidRequest(
                    "the bucket already has a target at that place and bucket",
                ));
            }
            let arn = found.map_or_else(
                || format!("{TARGET_ARN}{}:{id}:{}", new.region, new.target_bucket),
                |i| kept[i].target.arn.clone(),
            );
            let target = RemoteTarget {
                arn: arn.clone(),
                source_bucket: new.source_bucket,
                endpoint: new.endpoint,
                secure: new.secure,
                target_bucket: new.target_bucket,
                region: new.region,
                access_key: new.access_key,
                storage_class: new.storage_class,
                bandwidth_limit: new.bandwidth_limit,
                sync: new.sync,
                health_check_secs: new.health_check_secs,
                created_ms: found.map_or_else(now_ms, |i| kept[i].target.created_ms),
            };
            let entry = match (new.secrets, found) {
                (Some(secrets), _) => Kept {
                    secret: seal(&key, &arn, &secrets.secret_key),
                    session_token: secrets
                        .session_token
                        .as_deref()
                        .map(|token| seal(&key, &arn, token)),
                    target,
                },
                (None, Some(i)) => Kept {
                    secret: kept[i].secret.clone(),
                    session_token: kept[i].session_token.clone(),
                    target,
                },
                (None, None) => {
                    return Err(StoreError::InvalidRequest(
                        "a replication target needs a secret key",
                    ));
                }
            };
            match found {
                Some(i) => kept[i] = entry,
                None => kept.push(entry),
            }
            let json = serde_json::to_string(&kept).map_err(|_| StoreError::CorruptMetadata)?;
            system.set_setting(TARGETS, Some(&json))?;
            Ok(arn)
        })
        .await
    }

    /// Removes `bucket`'s target `arn`, unless a rule of its replication configuration
    /// still names it.
    pub async fn remove_replication_target(&self, bucket: &str, arn: &str) -> Result<()> {
        if let Some(config) = self.bucket_replication(bucket).await?
            && config.rules.iter().any(|r| r.destination.bucket == arn)
        {
            return Err(StoreError::InvalidRequest(
                "a replication rule still names this target: change the replication \
                 configuration first",
            ));
        }
        let (bucket, arn) = (bucket.to_owned(), arn.to_owned());
        self.blocking(move |inner| {
            inner.bucket(&bucket)?;
            let system = inner.system();
            let mut kept = read(system.setting(TARGETS)?.as_deref())?;
            let before = kept.len();
            kept.retain(|k| !(k.target.source_bucket == bucket && k.target.arn == arn));
            if kept.len() == before {
                return Err(StoreError::InvalidRequest("no such replication target"));
            }
            let json = serde_json::to_string(&kept).map_err(|_| StoreError::CorruptMetadata)?;
            system.set_setting(TARGETS, Some(&json))?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use teifs_crypto::LocalKms;
    use teifs_types::replication::{
        ReplicationConfig, ReplicationDestination, ReplicationFilter, ReplicationRule,
    };

    use super::*;
    use crate::{Layout, StoreOptions, Versioning};

    const SECRET: &str = "dummy-target-secret-0001";

    fn open(dir: &std::path::Path, keys: &std::path::Path) -> Store {
        let kms = Arc::new(LocalKms::open(keys.join("keyring.json")).unwrap());
        Store::open_with(
            dir,
            StoreOptions {
                kms: Some(kms),
                ..StoreOptions::default()
            },
        )
        .unwrap()
    }

    fn target(bucket: &str, secret: Option<&str>) -> NewTarget {
        NewTarget {
            arn: None,
            source_bucket: bucket.to_owned(),
            endpoint: "backup.example.com:9000".to_owned(),
            secure: true,
            target_bucket: "copy".to_owned(),
            region: "eu-west-1".to_owned(),
            access_key: "replicator".to_owned(),
            secrets: secret.map(|s| TargetSecrets {
                secret_key: Zeroizing::new(s.to_owned()),
                session_token: None,
            }),
            storage_class: String::new(),
            bandwidth_limit: 0,
            sync: false,
            health_check_secs: 0,
        }
    }

    /// Every file under `dir`, read whole.
    fn files(dir: &std::path::Path) -> Vec<Vec<u8>> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                found.extend(files(&path));
            } else {
                found.push(std::fs::read(&path).unwrap());
            }
        }
        found
    }

    #[tokio::test]
    async fn secrets_are_sealed_on_disk_and_open_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let store = open(dir.path(), keys.path());
        store.create_bucket("photos", Layout::Object).await.unwrap();
        let arn = store
            .add_replication_target(target("photos", Some(SECRET)))
            .await
            .unwrap();
        assert!(arn.starts_with("arn:minio:replication:eu-west-1:"), "{arn}");
        assert!(arn.ends_with(":copy"), "{arn}");
        drop(store);

        let encoded = STANDARD.encode(SECRET);
        for file in files(dir.path()) {
            for clear in [SECRET.as_bytes(), encoded.as_bytes()] {
                assert!(
                    !file.windows(clear.len()).any(|w| w == clear),
                    "the secret reached the disk in clear"
                );
            }
        }
        let store = open(dir.path(), keys.path());
        let secrets = store.replication_target_secrets(&arn).await.unwrap();
        assert_eq!(secrets.secret_key.as_str(), SECRET);
        assert!(secrets.session_token.is_none());
        let listed = store.replication_targets(Some("photos")).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].access_key, "replicator");
    }

    #[tokio::test]
    async fn the_same_place_keeps_its_arn_and_edits_keep_secrets_unless_given() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let store = open(dir.path(), keys.path());
        store.create_bucket("photos", Layout::Object).await.unwrap();
        let arn = store
            .add_replication_target(target("photos", Some(SECRET)))
            .await
            .unwrap();
        let again = store
            .add_replication_target(target("photos", Some("dummy-second")))
            .await
            .unwrap();
        assert_eq!(again, arn);
        assert_eq!(
            store
                .replication_target_secrets(&arn)
                .await
                .unwrap()
                .secret_key
                .as_str(),
            "dummy-second"
        );

        // An edit without secrets keeps them; a new target needs them.
        let mut edit = target("photos", None);
        edit.arn = Some(arn.clone());
        edit.sync = true;
        assert_eq!(store.add_replication_target(edit).await.unwrap(), arn);
        assert!(store.replication_target(&arn).await.unwrap().unwrap().sync);
        assert_eq!(
            store
                .replication_target_secrets(&arn)
                .await
                .unwrap()
                .secret_key
                .as_str(),
            "dummy-second"
        );
        let mut fresh = target("photos", None);
        fresh.target_bucket = "other".to_owned();
        assert!(store.add_replication_target(fresh).await.is_err());
        let mut unknown = target("photos", None);
        unknown.arn = Some("arn:minio:replication::nope:copy".to_owned());
        assert!(store.add_replication_target(unknown).await.is_err());
    }

    #[tokio::test]
    async fn a_target_a_rule_names_stays_until_the_rule_goes() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let store = open(dir.path(), keys.path());
        store.create_bucket("photos", Layout::Object).await.unwrap();
        store
            .set_bucket_versioning("photos", Versioning::Enabled)
            .await
            .unwrap();
        let arn = store
            .add_replication_target(target("photos", Some(SECRET)))
            .await
            .unwrap();
        let config = ReplicationConfig {
            role: String::new(),
            rules: vec![ReplicationRule {
                id: "r".to_owned(),
                priority: Some(1),
                enabled: true,
                filter: ReplicationFilter::All,
                delete_markers: Some(false),
                delete_replication: None,
                existing_objects: None,
                sse_kms_objects: None,
                replica_modifications: None,
                destination: ReplicationDestination {
                    bucket: arn.clone(),
                    account: None,
                    storage_class: None,
                    owner_override: false,
                    encryption: None,
                    replication_time: None,
                    metrics: None,
                },
            }],
        };
        store
            .set_bucket_replication("photos", Some(config))
            .await
            .unwrap();
        assert!(matches!(
            store.remove_replication_target("photos", &arn).await,
            Err(StoreError::InvalidRequest(why)) if why.contains("still names")
        ));
        store.set_bucket_replication("photos", None).await.unwrap();
        store
            .remove_replication_target("photos", &arn)
            .await
            .unwrap();
        assert!(store.replication_target(&arn).await.unwrap().is_none());
        assert!(
            store
                .remove_replication_target("photos", &arn)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn without_a_kms_targets_cant_be_added() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.create_bucket("photos", Layout::Object).await.unwrap();
        assert!(matches!(
            store
                .add_replication_target(target("photos", Some(SECRET)))
                .await,
            Err(StoreError::NoKms)
        ));
    }
}
