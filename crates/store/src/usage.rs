//! What each bucket holds, from the counters the index keeps as it changes: reading them
//! costs a row per bucket, however many objects there are. A folder bucket's files are
//! counted as the index knows them, so files added outside TeiFS count once the
//! `index-folders` job has found them.

use teifs_meta::{Layout, Usage};

use crate::{Bucket, Inner, Store, error::Result};

/// What a bucket holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketUsage {
    /// The bucket's name.
    pub name: String,
    /// How it stores objects.
    pub layout: Layout,
    /// Its objects, versions, delete markers and bytes.
    pub usage: Usage,
}

impl Store {
    /// What every bucket holds, by name.
    pub async fn usage(&self) -> Result<Vec<BucketUsage>> {
        self.blocking(Inner::usage).await
    }

    /// What one bucket holds.
    pub async fn bucket_usage(&self, bucket: &str) -> Result<Usage> {
        let name = bucket.to_owned();
        self.blocking(move |inner| {
            let (id, folder) = match inner.bucket(&name)? {
                Bucket::Object(bucket) => (Some(bucket.id), None),
                Bucket::Folder(bucket) => (bucket.versions.map(|v| v.id), Some(bucket.name)),
            };
            Ok(inner
                .lock()
                .bucket_usage(id.as_deref().unwrap_or_default(), folder.as_deref())?)
        })
        .await
    }
}

impl Inner {
    fn usage(&self) -> Result<Vec<BucketUsage>> {
        let buckets = self.buckets()?;
        let records = self.system().buckets()?;
        let counters = self.lock().usage()?;
        let versions = |name: &str| {
            records
                .iter()
                .find(|r| r.name == name)
                .and_then(|r| counters.versions.get(&r.id))
                .copied()
                .unwrap_or_default()
        };
        Ok(buckets
            .into_iter()
            .map(|bucket| {
                let files = match bucket.layout {
                    Layout::Object => Usage::default(),
                    Layout::Folder => counters
                        .files
                        .get(&bucket.name)
                        .copied()
                        .unwrap_or_default(),
                };
                BucketUsage {
                    usage: versions(&bucket.name) + files,
                    name: bucket.name,
                    layout: bucket.layout,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectAttrs, Versioning, test_util::in_both_layouts};

    in_both_layouts!(versions_markers_and_bytes_are_counted, quotas_are_kept);

    async fn quotas_are_kept(layout: Layout) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.create_bucket("docs", layout).await.unwrap();
        assert_eq!(store.bucket_quota("docs").await.unwrap(), None);
        store.set_bucket_quota("docs", Some(1024)).await.unwrap();
        assert_eq!(store.bucket_quota("docs").await.unwrap(), Some(1024));
        assert_eq!(
            store.bucket_settings("docs").await.unwrap().quota,
            Some(1024)
        );
        // Read again from the drive, not only from memory.
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.bucket_quota("docs").await.unwrap(), Some(1024));
        store.set_bucket_quota("docs", None).await.unwrap();
        assert_eq!(store.bucket_quota("docs").await.unwrap(), None);
        assert!(matches!(
            store.bucket_quota("nothing").await,
            Err(crate::StoreError::NoSuchBucket)
        ));
    }

    async fn versions_markers_and_bytes_are_counted(layout: Layout) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.create_bucket("docs", layout).await.unwrap();
        store
            .set_bucket_versioning("docs", Versioning::Enabled)
            .await
            .unwrap();
        store.create_bucket("plain", layout).await.unwrap();
        let put = |bucket: &'static str, key: &'static str, bytes: &'static [u8]| {
            let store = store.clone();
            async move {
                store
                    .put_bytes(bucket, key, bytes, ObjectAttrs::default())
                    .await
                    .unwrap();
            }
        };
        put("docs", "a.txt", b"one").await;
        put("docs", "a.txt", b"three").await;
        put("docs", "b.txt", b"four").await;
        store.delete("docs", "b.txt").await.unwrap();
        put("plain", "x", b"12345").await;
        put("plain", "x", b"123").await;
        let usage = store.usage().await.unwrap();
        let of = |name: &str| usage.iter().find(|u| u.name == name).unwrap().usage;
        assert_eq!(
            of("docs"),
            Usage {
                objects: 1,
                versions: 3,
                delete_markers: 1,
                bytes: 12
            }
        );
        assert_eq!(
            of("plain"),
            Usage {
                objects: 1,
                versions: 1,
                delete_markers: 0,
                bytes: 3
            }
        );
        for name in ["docs", "plain"] {
            assert_eq!(store.bucket_usage(name).await.unwrap(), of(name), "{name}");
        }
        store.delete("plain", "x").await.unwrap();
        store.delete_bucket("plain").await.unwrap();
        assert!(matches!(
            store.bucket_usage("plain").await,
            Err(crate::StoreError::NoSuchBucket)
        ));
        let usage = store.usage().await.unwrap();
        assert_eq!(
            usage.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(),
            ["docs"]
        );
    }
}
