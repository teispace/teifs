//! Healing a drive set: copies of the databases rebuilt where they failed, and every
//! object's shards checked on each drive that's up, those missing or damaged rebuilt
//! from the others. Runs while the set serves: an object removed meanwhile loses the
//! shards healed for it again.

use std::sync::Arc;

use serde::Serialize;

use crate::{BUCKETS_DIR, Store, error::Result, objects};

/// Data files looked up at a time.
const PAGE: usize = 256;

/// What a heal did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealReport {
    /// Objects (data files) checked.
    pub objects: u64,
    /// Of them, those given new shards.
    pub healed: u64,
    /// Shards written.
    pub shards: u64,
    /// Objects with too few sound shards left to rebuild from.
    pub unreadable: u64,
    /// Copies of the databases that still can't be used (on a drive that's failing).
    pub failed_copies: usize,
}

impl Store {
    /// Heals a drive set (nothing on a single drive): rebuilds the databases' failed
    /// copies, then checks every object's shards on the drives that are up and rebuilds
    /// those missing or damaged. Writes go on meanwhile.
    pub async fn heal_set(&self) -> Result<HealReport> {
        let Some(set) = self.inner.set.clone() else {
            return Ok(HealReport::default());
        };
        let failed_copies = self
            .blocking(|inner| {
                let index = inner.lock().heal_copies()?;
                let system = inner.system().heal_copies()?;
                Ok(index
                    .iter()
                    .chain(&system)
                    .filter(|(_, state)| *state != teifs_meta::CopyState::Current)
                    .count())
            })
            .await?;
        let mut report = HealReport {
            failed_copies,
            ..HealReport::default()
        };
        let mut after = String::new();
        loop {
            let from = after.clone();
            let page = self
                .blocking(move |inner| Ok(inner.lock().data_files_after(&from, PAGE)?))
                .await?;
            let Some((_, last)) = page.last() else {
                break;
            };
            after.clone_from(last);
            for (bucket_id, object_id) in page {
                report.objects += 1;
                let set = Arc::clone(&set);
                let healed = self
                    .blocking(move |inner| {
                        let dir = inner.system_dir.join(BUCKETS_DIR).join(&bucket_id);
                        let path = objects::data_file(&dir, &object_id);
                        let healed = match set.heal_file(&path, &object_id) {
                            Ok(healed) => healed,
                            // Removed since it was listed.
                            Err(crate::StoreError::Io(err))
                                if err.kind() == std::io::ErrorKind::NotFound =>
                            {
                                return Ok(None);
                            }
                            Err(err) => {
                                tracing::error!(object = %object_id, error = %err, "an object can't be healed");
                                return Ok(Some(Err(())));
                            }
                        };
                        // Removed while it was healed: its new shards go too.
                        if !healed.is_empty() && !inner.lock().object_in_use(&object_id)? {
                            set.remove(&path);
                            return Ok(None);
                        }
                        Ok(Some(Ok(healed.len())))
                    })
                    .await?;
                match healed {
                    Some(Ok(0)) | None => {}
                    Some(Ok(shards)) => {
                        report.healed += 1;
                        report.shards += shards as u64;
                    }
                    Some(Err(())) => report.unreadable += 1,
                }
            }
        }
        if report.healed > 0 || report.unreadable > 0 {
            tracing::info!(
                objects = report.objects,
                healed = report.healed,
                shards = report.shards,
                unreadable = report.unreadable,
                "the drive set was healed"
            );
        }
        Ok(report)
    }
}
