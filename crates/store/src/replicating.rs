//! Where versions stand in replication: which still wait (found again after a restart,
//! since the status is kept with each version), and each destination's outcome.

use std::collections::BTreeMap;

use teifs_meta::QueuedDelete;
use teifs_types::{
    Retention,
    replication::{ReplicationConfig, ReplicationStatus, VersionReplication},
};

use crate::{ObjectAttrs, ObjectInfo, Store, StoreError, VersionsQuery, error::Result, now_ms};

/// A version waiting to be replicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// Its key.
    pub key: String,
    /// Its version id.
    pub version_id: String,
    /// The destinations (ARNs) it still waits for.
    pub destinations: Vec<String>,
    /// Those of them that have it, and wait only for what changed in its metadata.
    pub metadata: Vec<String>,
    /// Whether it's a delete marker.
    pub delete_marker: bool,
    /// When it was made.
    pub modified: std::time::SystemTime,
}

/// The removal of `key`'s version `version_id` (a delete marker or not, described by
/// `attrs`) to queue for the destinations `config` sends it to
/// ([`ReplicationConfig::removal_destinations`]): a marker's removal follows the
/// marker.
pub(crate) fn removal(
    config: &ReplicationConfig,
    (key, version_id): (&str, &str),
    delete_marker: bool,
    attrs: &ObjectAttrs,
) -> QueuedDelete {
    let sent_to: Vec<&str> = attrs
        .replication
        .iter()
        .filter(|_| delete_marker)
        .flat_map(|r| r.targets.keys().map(String::as_str))
        .collect();
    // A version's tags pick the rules, as for its replication; whether it's SSE-KMS
    // doesn't (a destination without it takes the removal as done).
    let tags = if delete_marker {
        std::collections::BTreeMap::new()
    } else {
        attrs.tags.clone()
    };
    QueuedDelete {
        key: key.to_owned(),
        version_id: version_id.to_owned(),
        delete_marker,
        destinations: config.removal_destinations(key, (&tags, false), &sent_to),
    }
}

/// Records that a version's metadata changed: it waits again for its destinations.
pub(crate) fn changed(attrs: &mut ObjectAttrs) {
    attrs.replication = attrs.replication.take().map(VersionReplication::changed);
}

/// What a replica's metadata becomes when its source's changed; `None` leaves a part as
/// it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaMetadata {
    /// Its tags.
    pub tags: Option<BTreeMap<String, String>>,
    /// Its retention.
    pub retention: Option<Retention>,
    /// Its legal hold.
    pub legal_hold: Option<bool>,
}

/// How many versions a page of the search reads.
const PAGE: usize = 1_000;

impl Store {
    /// The versions of `bucket` still waiting for a destination, by key and each key's
    /// newest first: about `limit` of them, never only some of a key's (so a key's
    /// versions can be replicated oldest first).
    pub async fn waiting_replication(&self, bucket: &str, limit: usize) -> Result<Vec<Waiting>> {
        let mut found: Vec<Waiting> = Vec::new();
        let mut query = VersionsQuery {
            max_keys: PAGE,
            ..VersionsQuery::default()
        };
        loop {
            let page = self.list_versions(bucket, query.clone()).await?;
            for version in page.versions {
                let key = &version.info.key;
                if found.len() >= limit && found.last().is_some_and(|last| &last.key != key) {
                    return Ok(found);
                }
                let (Some(replication), Some(version_id)) =
                    (&version.info.attrs.replication, &version.info.version_id)
                else {
                    continue;
                };
                let destinations: Vec<String> = replication.waiting().map(str::to_owned).collect();
                if !destinations.is_empty() {
                    found.push(Waiting {
                        key: key.clone(),
                        version_id: version_id.clone(),
                        metadata: destinations
                            .iter()
                            .filter(|arn| replication.metadata.contains(*arn))
                            .cloned()
                            .collect(),
                        destinations,
                        delete_marker: version.delete_marker,
                        modified: version.info.modified,
                    });
                }
            }
            match page.next {
                Some((key, version)) if page.truncated => {
                    query.key_marker = Some(key);
                    query.version_marker = version;
                }
                _ => return Ok(found),
            }
        }
    }

    /// Records where `key`'s version `version_id` stands with the destination `arn`.
    /// A version that doesn't wait for `arn` (any more) is left as it is.
    pub async fn set_replication_status(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        arn: &str,
        status: ReplicationStatus,
    ) -> Result<()> {
        let record = {
            let arn = arn.to_owned();
            move |attrs: &mut ObjectAttrs| {
                if let Some(replication) = attrs.replication.take() {
                    attrs.replication = Some(replication.with(&arn, status));
                }
            }
        };
        let changed = self
            .change_attrs(bucket, key, Some(version_id), move |attrs| {
                record(attrs);
                Ok(())
            })
            .await;
        match changed {
            // Gone meanwhile: nothing to record.
            Ok(_) | Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => Ok(()),
            Err(StoreError::DeleteMarker { .. }) => {
                self.set_marker_replication(bucket, key, version_id, arn, status)
                    .await
            }
            Err(err) => Err(err),
        }
    }

    /// Records where the delete marker `version_id` of `key` stands with `arn` (a
    /// marker's attributes are in the version store, in either layout).
    async fn set_marker_replication(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        arn: &str,
        status: ReplicationStatus,
    ) -> Result<()> {
        let (bucket, key) = (bucket.to_owned(), key.to_owned());
        let (version_id, arn) = (version_id.to_owned(), arn.to_owned());
        self.blocking(move |inner| {
            let found = inner.bucket(&bucket)?;
            let Some(versions) = found.versions() else {
                return Ok(());
            };
            let conn = inner.lock();
            let Some(mut row) = conn.version(&versions.id, &key, &version_id)? else {
                return Ok(());
            };
            if let (true, Some(replication)) = (row.delete_marker, row.attrs.replication.take()) {
                row.attrs.replication = Some(replication.with(&arn, status));
                conn.set_version_attrs(&versions.id, &key, &version_id, &row.attrs, None)?;
            }
            Ok(())
        })
        .await
    }

    /// Changes the metadata of the replica `version_id` of `key` as its source's
    /// changed. Only a replica's metadata changes so; a retention is changed as by one
    /// who may bypass governance (the source's was), never shortening a compliance one.
    pub async fn update_replica_metadata(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        update: ReplicaMetadata,
    ) -> Result<ObjectInfo> {
        if update.retention.is_some() || update.legal_hold.is_some() {
            self.require_lock(bucket).await?;
        }
        let now = now_ms();
        self.change_attrs(bucket, key, Some(version_id), move |attrs| {
            let replica = attrs.replication.as_ref().map(|r| r.status);
            if replica != Some(ReplicationStatus::Replica) {
                return Err(StoreError::InvalidRequest(
                    "only a replica's metadata changes as its source's",
                ));
            }
            if let Some(tags) = update.tags {
                attrs.tags = tags;
            }
            if let Some(retention) = update.retention
                && attrs.retention.as_ref() != Some(&retention)
            {
                crate::lock::check_retention_change(
                    attrs.retention.as_ref(),
                    Some(&retention),
                    true,
                    now,
                )?;
                attrs.retention = Some(retention);
            }
            if let Some(on) = update.legal_hold {
                attrs.legal_hold = Some(on);
            }
            Ok(())
        })
        .await
    }

    /// The removals of versions of `bucket` still to be replicated, oldest first: at
    /// most `limit`.
    pub async fn waiting_removals(&self, bucket: &str, limit: usize) -> Result<Vec<QueuedDelete>> {
        let bucket = bucket.to_owned();
        self.blocking(move |inner| {
            let found = inner.bucket(&bucket)?;
            let Some(versions) = found.versions() else {
                return Ok(Vec::new());
            };
            Ok(inner.lock().replicated_deletes(&versions.id, limit)?)
        })
        .await
    }

    /// Records that the removal of `key`'s version `version_id` is still to reach only
    /// `destinations` (none: it's done).
    pub async fn set_removal_destinations(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        destinations: Vec<String>,
    ) -> Result<()> {
        let (bucket, key, version_id) = (bucket.to_owned(), key.to_owned(), version_id.to_owned());
        self.blocking(move |inner| {
            let found = inner.bucket(&bucket)?;
            let Some(versions) = found.versions() else {
                return Ok(());
            };
            Ok(inner.lock().set_replicated_delete(
                &versions.id,
                &key,
                &version_id,
                &destinations,
            )?)
        })
        .await
    }
}
