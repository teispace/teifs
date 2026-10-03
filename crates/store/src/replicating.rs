//! Where versions stand in replication: which still wait (found again after a restart,
//! since the status is kept with each version), and each destination's outcome.

use teifs_types::replication::ReplicationStatus;

use crate::{ObjectAttrs, Store, StoreError, VersionsQuery, error::Result};

/// A version waiting to be replicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// Its key.
    pub key: String,
    /// Its version id.
    pub version_id: String,
    /// The destinations (ARNs) it still waits for.
    pub destinations: Vec<String>,
    /// Whether it's a delete marker.
    pub delete_marker: bool,
    /// When it was made.
    pub modified: std::time::SystemTime,
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
}
