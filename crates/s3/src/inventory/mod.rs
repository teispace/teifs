//! Inventory reports: what S3 Inventory delivers for a bucket's inventory
//! configurations, daily or weekly (on Sundays, UTC). Each report is gzipped CSV data
//! files under `{prefix}/{source}/{id}/data/`, then `{prefix}/{source}/{id}/hive/dt=…/
//! symlink.txt` listing them, then `{prefix}/{source}/{id}/{time}/manifest.json` and its
//! `manifest.checksum` (the manifest's MD5), written last. They're written by
//! `s3.amazonaws.com`, so the destination's policy must let that service put them, as on
//! AWS. When each configuration last had its report is kept with the drive, so a restart
//! neither repeats nor skips one.

mod report;

use std::{collections::BTreeMap, fmt::Write as _, time::Duration};

use bytes::Bytes;
use md5::{Digest, Md5};
use serde::Serialize;
use teifs_store::{After, ListQuery, ObjectVersion, Store, VersionsQuery};
use teifs_types::configs::{Frequency, InventoryConfig, InventoryFormat, ReportEncryption};
use tokio_util::sync::CancellationToken;

use self::report::{DataFiles, Entry, Schema};
use crate::{
    delivery::{Delivery, Encryption, Undelivered},
    drive::Drive,
    errors::from_store,
};

/// The service that writes reports, as the destination's policy names it.
pub(crate) const SERVICE: &str = "s3.amazonaws.com";
/// A data file this big (compressed) is closed and another started.
const DATA_FILE_BYTES: usize = 32 << 20;
/// How many objects are read from the bucket at a time.
const PAGE: usize = 1000;
/// The drive's note of when each configuration last had its report.
const NOTE: &str = "inventory";

/// When each bucket's configurations last had their reports: the period (day or week)
/// of each, by bucket and id.
type Done = BTreeMap<String, BTreeMap<String, i64>>;

/// Makes the reports that are due; the server runs it.
#[derive(Debug)]
pub(crate) struct Worker {
    drive: Drive,
    store: Store,
    data_file_bytes: usize,
    page: usize,
}

impl Worker {
    pub(crate) fn new(drive: Drive, store: Store) -> Self {
        Self {
            drive,
            store,
            data_file_bytes: DATA_FILE_BYTES,
            page: PAGE,
        }
    }

    /// Makes the reports that are due, and then each that becomes due, until
    /// `stopping`. A report being made then stops after the page it's reading (so
    /// nothing it started is left running) and is made again after the next start.
    pub(crate) async fn run(self, stopping: CancellationToken) {
        let mut tick = tokio::time::interval(check_every(self.store.day_ms()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stopping.cancelled() => break,
                _ = tick.tick() => self.report_due(&stopping).await,
            }
        }
    }

    /// Makes each enabled configuration's report that's due: one per day or week, the
    /// first as soon as it's configured.
    async fn report_due(&self, stopping: &CancellationToken) {
        let day_ms = self.store.day_ms();
        let done = self.done().await;
        let buckets = match self.store.list_buckets().await {
            Ok(buckets) => buckets,
            Err(err) => {
                tracing::warn!(error = %err, "couldn't list the buckets for their inventory reports");
                return;
            }
        };
        let mut next = Done::new();
        for bucket in buckets {
            if stopping.is_cancelled() {
                return;
            }
            let bucket = bucket.name;
            let last = done.get(&bucket);
            let configurations = match self.store.bucket_configurations(&bucket).await {
                Ok(configurations) => configurations,
                Err(err) => {
                    tracing::warn!(bucket, error = %err, "couldn't read the bucket's inventory configurations");
                    if let Some(last) = last {
                        next.insert(bucket, last.clone());
                    }
                    continue;
                }
            };
            for (id, config) in configurations.inventory.iter().filter(|(_, c)| c.enabled) {
                let period = period(config.frequency, now_ms(), day_ms);
                let last = last.and_then(|last| last.get(id)).copied();
                let made = if last == Some(period) {
                    Some(period)
                } else {
                    self.make((&bucket, id, config), period, last, stopping)
                        .await
                };
                if let Some(made) = made {
                    next.entry(bucket.clone())
                        .or_default()
                        .insert(id.clone(), made);
                }
            }
        }
        if next != done {
            self.keep(&next).await;
        }
    }

    /// Makes a report, and says which period was last reported: this one, unless the
    /// report may yet be made (then `last`).
    async fn make(
        &self,
        (bucket, id, config): (&str, &str, &InventoryConfig),
        period: i64,
        last: Option<i64>,
        stopping: &CancellationToken,
    ) -> Option<i64> {
        match self.report(bucket, id, config, stopping).await {
            Ok(()) => Some(period),
            Err(Undelivered::Refused(why)) => {
                tracing::warn!(bucket, id, why, "an inventory report wasn't delivered");
                Some(period)
            }
            Err(Undelivered::Failed(why)) => {
                tracing::warn!(
                    bucket,
                    id,
                    why,
                    "an inventory report wasn't delivered; will try again"
                );
                last
            }
        }
    }

    async fn done(&self) -> Done {
        match self.store.note(NOTE).await {
            Ok(Some(note)) => serde_json::from_str(&note).unwrap_or_default(),
            Ok(None) => Done::new(),
            Err(err) => {
                tracing::warn!(error = %err, "couldn't read when inventory reports were made");
                Done::new()
            }
        }
    }

    async fn keep(&self, done: &Done) {
        let note = (!done.is_empty()).then(|| serde_json::to_string(done).unwrap_or_default());
        if let Err(err) = self.store.set_note(NOTE, note).await {
            tracing::warn!(error = %err, "couldn't keep when inventory reports were made");
        }
    }

    /// Makes and delivers one report of `bucket` now.
    async fn report(
        &self,
        bucket: &str,
        id: &str,
        config: &InventoryConfig,
        stopping: &CancellationToken,
    ) -> Result<(), Undelivered> {
        let destination = &config.destination;
        if destination.format != InventoryFormat::Csv {
            return Err(Undelivered::Refused(
                "only CSV inventory reports are made".to_owned(),
            ));
        }
        let created_ms = now_ms();
        let encryption = destination.encryption.as_ref().map(|e| match e {
            ReportEncryption::S3 => Encryption::S3,
            ReportEncryption::Kms(key) => Encryption::Kms(key),
        });
        let delivery = |content_type| Delivery {
            service: SERVICE,
            source: bucket,
            target: &destination.bucket,
            content_type,
            canned_acl: Some("bucket-owner-full-control"),
            acl: None,
            encryption,
        };
        let base = base_key(destination.prefix.as_deref(), bucket, id);
        let schema = Schema::of(config);
        let files = self
            .data((bucket, config, &schema), stopping, |data| {
                let key = format!("{base}/data/{}.csv.gz", uuid::Uuid::new_v4());
                let delivery = delivery("application/gzip");
                async move {
                    let file = ManifestFile::of(key, &data);
                    self.drive
                        .deliver(&delivery, &file.key, Bytes::from(data))
                        .await?;
                    Ok(file)
                }
            })
            .await?;
        let symlink = files.iter().fold(String::new(), |mut out, file| {
            let _ = writeln!(out, "s3://{}/{}", destination.bucket, file.key);
            out
        });
        let manifest = Manifest {
            source_bucket: bucket,
            destination_bucket: format!("arn:aws:s3:::{}", destination.bucket),
            version: "2016-11-30",
            creation_timestamp: created_ms.to_string(),
            file_format: "CSV",
            file_schema: schema.names(),
            files,
        };
        let manifest = serde_json::to_vec(&manifest).unwrap_or_default();
        let checksum = hex(&Md5::digest(&manifest));
        let (folder, hive) = folders(created_ms);
        for (key, content_type, data) in [
            (
                format!("{base}/hive/dt={hive}/symlink.txt"),
                "text/plain",
                symlink.into_bytes(),
            ),
            (
                format!("{base}/{folder}/manifest.json"),
                "application/json",
                manifest,
            ),
            (
                format!("{base}/{folder}/manifest.checksum"),
                "text/plain",
                checksum.into_bytes(),
            ),
        ] {
            self.drive
                .deliver(&delivery(content_type), &key, Bytes::from(data))
                .await?;
        }
        Ok(())
    }

    /// Lists what the report covers into data files, delivering each with `deliver` as
    /// it's closed.
    async fn data<F, Fut>(
        &self,
        (bucket, config, schema): (&str, &InventoryConfig, &Schema),
        stopping: &CancellationToken,
        deliver: F,
    ) -> Result<Vec<ManifestFile>, Undelivered>
    where
        F: Fn(Vec<u8>) -> Fut,
        Fut: Future<Output = Result<ManifestFile, Undelivered>>,
    {
        let failed = |err: std::io::Error| Undelivered::Failed(err.to_string());
        let store_error = |err| Undelivered::from(from_store(err));
        let locked = self
            .store
            .bucket_object_lock(bucket)
            .await
            .map_err(store_error)?
            .is_some();
        let mut data = DataFiles::new(self.data_file_bytes);
        let mut files = Vec::new();
        let mut page = Page::Start;
        let mut rows = String::new();
        loop {
            if stopping.is_cancelled() {
                return Err(Undelivered::Failed("the server is stopping".to_owned()));
            }
            let (versions, next) = self.page(bucket, config, page).await.map_err(store_error)?;
            rows.clear();
            for version in &versions {
                let expiry_ms = if schema.needs_expiry() && !version.delete_marker {
                    let expiry = self.store.expiry(bucket, &version.info).await;
                    expiry.map_err(store_error)?.map(|expiry| expiry.at_ms)
                } else {
                    None
                };
                let entry = Entry {
                    version,
                    expiry_ms,
                    locked,
                };
                report::row(schema, bucket, &entry, &mut rows);
            }
            if let Some(file) = data.push(&rows).map_err(failed)? {
                files.push(deliver(file).await?);
            }
            match next {
                Some(next) => page = next,
                None => break,
            }
        }
        if let Some(file) = data.finish().map_err(failed)? {
            files.push(deliver(file).await?);
        }
        Ok(files)
    }

    /// One page of what the report covers: every version, or each current object.
    async fn page(
        &self,
        bucket: &str,
        config: &InventoryConfig,
        page: Page,
    ) -> teifs_store::Result<(Vec<ObjectVersion>, Option<Page>)> {
        let prefix = config.prefix.clone().unwrap_or_default();
        if config.all_versions {
            let (key_marker, version_marker) = match page {
                Page::Versions(key, version) => (Some(key), version),
                Page::Start | Page::Objects(_) => (None, None),
            };
            let listing = self
                .store
                .list_versions(
                    bucket,
                    VersionsQuery {
                        prefix,
                        delimiter: None,
                        key_marker,
                        version_marker,
                        max_keys: self.page,
                    },
                )
                .await?;
            let next = listing
                .next
                .filter(|_| listing.truncated)
                .map(|(key, version)| Page::Versions(key, version));
            return Ok((listing.versions, next));
        }
        let after = match page {
            Page::Objects(after) => Some(after),
            Page::Start | Page::Versions(..) => None,
        };
        let listing = self
            .store
            .list(
                bucket,
                ListQuery {
                    prefix,
                    delimiter: None,
                    after,
                    max_keys: self.page,
                },
            )
            .await?;
        let next = listing
            .next
            .filter(|_| listing.truncated)
            .map(Page::Objects);
        let versions = listing
            .objects
            .into_iter()
            .map(|info| ObjectVersion {
                info,
                latest: true,
                delete_marker: false,
            })
            .collect();
        Ok((versions, next))
    }
}

/// Where a listing for a report goes on.
enum Page {
    Start,
    Objects(After),
    Versions(String, Option<String>),
}

/// `manifest.json`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest<'a> {
    source_bucket: &'a str,
    destination_bucket: String,
    version: &'static str,
    creation_timestamp: String,
    file_format: &'static str,
    file_schema: String,
    files: Vec<ManifestFile>,
}

/// A data file, as the manifest lists it.
#[derive(Debug, Serialize)]
struct ManifestFile {
    key: String,
    size: usize,
    #[serde(rename = "MD5checksum")]
    md5: String,
}

impl ManifestFile {
    fn of(key: String, data: &[u8]) -> Self {
        Self {
            key,
            size: data.len(),
            md5: hex(&Md5::digest(data)),
        }
    }
}

/// What a configuration's report keys start with: `{prefix}/{source}/{id}`.
fn base_key(prefix: Option<&str>, source: &str, id: &str) -> String {
    match prefix.map(|prefix| prefix.trim_end_matches('/')) {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}/{source}/{id}"),
        _ => format!("{source}/{id}"),
    }
}

/// The folders of a report made at `ms`: its manifest's (`2024-08-21T15-28Z`) and its
/// Hive partition's (`2024-08-21-15-28`).
fn folders(ms: i64) -> (String, String) {
    let iso = report::iso(ms);
    let (date, time) = (&iso[..10], &iso[11..16]);
    let time = time.replace(':', "-");
    (format!("{date}T{time}Z"), format!("{date}-{time}"))
}

/// Which day (for a daily report) or week starting on a Sunday (for a weekly one) `ms`
/// is in, counting days of `day_ms` from the Unix epoch.
fn period(frequency: Frequency, ms: i64, day_ms: i64) -> i64 {
    let day = ms.div_euclid(day_ms);
    match frequency {
        Frequency::Daily => day,
        // 1970-01-01 was a Thursday: day 3 was the first Sunday.
        Frequency::Weekly => (day + 4).div_euclid(7),
    }
}

/// How often due reports are looked for: 96 times a day, at most every 15 minutes.
fn check_every(day_ms: i64) -> Duration {
    Duration::from_millis(
        u64::try_from(day_ms / 96)
            .unwrap_or(0)
            .clamp(50, 15 * 60 * 1000),
    )
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use std::{
        io::Read,
        sync::{Arc, Mutex},
    };

    use teifs_store::{Expiration, Layout, Lifecycle, LifecycleRule, RuleFilter, Versioning};
    use teifs_types::{
        ObjectAttrs,
        configs::{InventoryDestination, InventoryField},
    };

    use super::*;

    /// A store with buckets `src` (versioned, with `a`, `b` and `c` written twice), `dst`
    /// and `folder` (a folder bucket), and a worker that reads two objects a page and
    /// closes a data file at every page.
    async fn setup() -> (tempfile::TempDir, Worker) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for (bucket, layout) in [
            ("src", Layout::Object),
            ("dst", Layout::Object),
            ("folder", Layout::Folder),
        ] {
            store.create_bucket(bucket, layout).await.unwrap();
        }
        store
            .set_bucket_versioning("src", Versioning::Enabled)
            .await
            .unwrap();
        for key in ["a", "b", "c", "a", "b", "c"] {
            store
                .put_bytes("src", key, b"hello", ObjectAttrs::default())
                .await
                .unwrap();
        }
        let notifier = Arc::new(teifs_notify::Notifier::none());
        let drive = Drive::new(store.clone(), Layout::Object, false, notifier, None);
        let worker = Worker {
            drive,
            store,
            data_file_bytes: 1,
            page: 2,
        };
        (dir, worker)
    }

    fn config(destination: &str, all_versions: bool) -> InventoryConfig {
        InventoryConfig {
            enabled: true,
            prefix: None,
            destination: InventoryDestination {
                bucket: destination.to_owned(),
                account: None,
                format: InventoryFormat::Csv,
                prefix: None,
                encryption: None,
            },
            all_versions,
            fields: Vec::new(),
            frequency: Frequency::Daily,
        }
    }

    /// The data files a report of `config` makes, unzipped.
    async fn data(worker: &Worker, config: &InventoryConfig) -> Vec<String> {
        let files = Arc::new(Mutex::new(Vec::new()));
        let schema = Schema::of(config);
        let made = worker
            .data(
                ("src", config, &schema),
                &CancellationToken::new(),
                |data| {
                    let files = Arc::clone(&files);
                    async move {
                        let mut text = String::new();
                        flate2::read::GzDecoder::new(&data[..])
                            .read_to_string(&mut text)
                            .unwrap();
                        files.lock().unwrap().push(text);
                        Ok(ManifestFile::of("k".to_owned(), &data))
                    }
                },
            )
            .await
            .unwrap();
        let files = files.lock().unwrap().clone();
        assert_eq!(made.len(), files.len());
        files
    }

    #[tokio::test]
    async fn every_page_is_read_and_files_close_as_they_fill() {
        let (_dir, worker) = setup().await;
        // Six versions, two a page: three files.
        let files = data(&worker, &config("dst", true)).await;
        assert_eq!(files.len(), 3, "{files:?}");
        assert!(
            files.iter().all(|file| file.lines().count() == 2),
            "{files:?}"
        );
        // Three current objects: two pages.
        let files = data(&worker, &config("dst", false)).await;
        assert_eq!(files.concat().lines().count(), 3, "{files:?}");
        assert_eq!(files.len(), 2, "{files:?}");
        // A stopping server stops a report before its next page.
        let stopping = CancellationToken::new();
        stopping.cancel();
        let config = config("dst", true);
        let stopped = worker
            .data(
                ("src", &config, &Schema::of(&config)),
                &stopping,
                |_| async { Ok(ManifestFile::of(String::new(), b"")) },
            )
            .await;
        assert!(matches!(stopped, Err(Undelivered::Failed(_))));
    }

    #[tokio::test]
    async fn lifecycle_expiry_dates_are_reported() {
        let (_dir, worker) = setup().await;
        let rule = LifecycleRule {
            id: "old".to_owned(),
            enabled: true,
            filter: RuleFilter::All,
            expiration: Some(Expiration::Days(1)),
            noncurrent_expiration: None,
            abort_uploads_after_days: None,
        };
        worker
            .store
            .set_bucket_lifecycle(
                "src",
                Some(Lifecycle {
                    rules: vec![rule],
                    transition_minimum_size: None,
                }),
            )
            .await
            .unwrap();
        let mut config = config("dst", false);
        config.fields = vec![InventoryField::LifecycleExpirationDate];
        let rows = data(&worker, &config).await.concat();
        assert!(
            rows.lines().all(|row| row.ends_with("T00:00:00.000Z\"")),
            "{rows}"
        );
    }

    #[tokio::test]
    async fn encryption_is_asked_of_the_destination() {
        let (_dir, worker) = setup().await;
        let stopping = CancellationToken::new();
        let plain = config("folder", false);
        worker
            .report("src", "plain", &plain, &stopping)
            .await
            .unwrap();
        let mut encrypted = plain.clone();
        encrypted.destination.encryption = Some(ReportEncryption::S3);
        // A folder bucket takes no encryption.
        let refused = worker.report("src", "sse", &encrypted, &stopping).await;
        assert!(
            matches!(refused, Err(Undelivered::Refused(_))),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn disabled_configurations_wait_and_refused_reports_are_not_retried() {
        let (_dir, worker) = setup().await;
        let mut disabled = config("dst", false);
        disabled.enabled = false;
        for (id, config) in [("gone", config("nowhere", false)), ("off", disabled)] {
            worker
                .store
                .put_configuration("src", teifs_types::configs::Kind::Inventory, id, move |c| {
                    c.inventory.insert(id.to_owned(), config);
                })
                .await
                .unwrap();
        }
        worker.report_due(&CancellationToken::new()).await;
        let done: Done =
            serde_json::from_str(&worker.store.note(NOTE).await.unwrap().unwrap()).unwrap();
        let day = period(Frequency::Daily, now_ms(), worker.store.day_ms());
        assert_eq!(done["src"], BTreeMap::from([("gone".to_owned(), day)]));
        let listed = worker
            .store
            .list(
                "dst",
                ListQuery {
                    max_keys: 10,
                    ..ListQuery::default()
                },
            )
            .await
            .unwrap();
        assert!(listed.objects.is_empty());
    }

    const DAY: i64 = 86_400_000;

    #[test]
    fn weeks_start_on_sundays() {
        // 2026-10-03 is a Saturday, 2026-10-04 a Sunday.
        let saturday = 1_791_072_000_000 - 1;
        let sunday = 1_791_072_000_000;
        assert_eq!(report::iso(sunday), "2026-10-04T00:00:00.000Z");
        let week = period(Frequency::Weekly, sunday, DAY);
        assert_eq!(period(Frequency::Weekly, saturday, DAY), week - 1);
        assert_eq!(period(Frequency::Weekly, sunday + 7 * DAY - 1, DAY), week);
        assert_eq!(period(Frequency::Weekly, sunday + 7 * DAY, DAY), week + 1);
        assert_eq!(period(Frequency::Daily, sunday, DAY), sunday / DAY);
        assert_eq!(period(Frequency::Daily, saturday, DAY), sunday / DAY - 1);
        assert_eq!(period(Frequency::Daily, 5_000, 2_000), 2);
    }

    #[test]
    fn keys_and_folders_are_s3s() {
        assert_eq!(base_key(None, "photos", "all"), "photos/all");
        assert_eq!(base_key(Some(""), "photos", "all"), "photos/all");
        assert_eq!(
            base_key(Some("reports/"), "photos", "all"),
            "reports/photos/all"
        );
        assert_eq!(base_key(Some("r"), "photos", "all"), "r/photos/all");
        assert_eq!(
            folders(1_724_254_106_123),
            (
                "2024-08-21T15-28Z".to_owned(),
                "2024-08-21-15-28".to_owned()
            )
        );
    }

    #[test]
    fn reports_are_looked_for_often_enough() {
        assert_eq!(check_every(DAY), Duration::from_mins(15));
        assert_eq!(check_every(2 * DAY), Duration::from_mins(15));
        assert_eq!(check_every(9_600), Duration::from_millis(100));
        assert_eq!(check_every(1), Duration::from_millis(50));
    }

    #[test]
    fn checksums_are_lowercase_hex() {
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(
            ManifestFile::of("k".to_owned(), b"").md5,
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }
}
