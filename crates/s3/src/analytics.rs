//! Storage class analysis exports: what S3's storage class analysis writes for a
//! bucket's analytics configurations that export. Each day's figures are added to one
//! CSV per configuration, `{prefix}/{source}/{id}.csv` in the destination, sorted by
//! date within age group with the `ALL` rows last, as S3's are. They're written by
//! `s3.amazonaws.com`, so the destination's policy must let that service put them.
//!
//! Requests are counted as they're answered ([`Activity`], fed by the request metrics
//! worker): successful `GET`s and `PUT`s of the objects a configuration matches, by the
//! object's age. What's stored is read from the bucket when the day's figures are
//! exported, after the day ends. The day's counts are kept with the drive every check,
//! so a restart loses at most a few minutes of them.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use teifs_store::{After, ListQuery, Store, StoreError};
use teifs_types::{ObjectInfo, configs::AnalyticsConfig};
use tokio::io::AsyncReadExt as _;
use tokio_util::sync::CancellationToken;

use crate::{
    delivery::{Delivery, Undelivered},
    drive::Drive,
    errors::from_store,
    inventory,
};

/// The day each configuration last exported, by bucket and id.
const NOTE: &str = "analytics";
/// The counts of the days not yet exported.
const ACTIVITY_NOTE: &str = "analytics-activity";
/// Objects smaller than this are only in the `ALL` rows.
const MIN_AGED: u64 = 128 * 1024;
/// How many objects are read from the bucket at a time.
const PAGE: usize = 1000;
/// Bytes in the export's megabyte.
const MB: f64 = 1024.0 * 1024.0;
/// The days of counts kept: today's, and the days before still to be exported.
const DAYS_KEPT: i64 = 7;
/// The export's columns.
const HEADER: &str = "Date,ConfigId,Filter,StorageClass,ObjectAge,ObjectCount,DataUploaded_MB,\
                      Storage_MB,DataRetrieved_MB,GetRequestCount,CumulativeAccessRatio,\
                      ObjectAgeForSIATransition,RecommendedObjectAgeForSIATransition";
/// The age groups: each one's first day and its name in the export. Then `ALL`.
const GROUPS: [(i64, &str); 12] = [
    (0, "000-014"),
    (15, "015-029"),
    (30, "030-044"),
    (45, "045-059"),
    (60, "060-074"),
    (75, "075-089"),
    (90, "090-119"),
    (120, "120-149"),
    (150, "150-179"),
    (180, "180-364"),
    (365, "365-729"),
    (730, "730+"),
];
const ALL: usize = GROUPS.len();

/// The age group of an object `age_days` old and `size` bytes big: none (only `ALL`)
/// for an object under 128 KiB.
pub(crate) fn group(age_days: i64, size: u64) -> Option<usize> {
    (size >= MIN_AGED).then(|| {
        GROUPS
            .iter()
            .rposition(|(first, _)| age_days >= *first)
            .unwrap_or(0)
    })
}

/// A day's requests for a configuration, in one age group or all of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Counts {
    /// `GET`s and `PUT`s.
    pub(crate) requests: u64,
    /// Bytes sent by `GET`s.
    pub(crate) retrieved: u64,
    /// Bytes stored by `PUT`s (not multipart uploads, as on S3).
    pub(crate) uploaded: u64,
}

impl Counts {
    fn add(&mut self, other: Self) {
        self.requests += other.requests;
        self.retrieved += other.retrieved;
        self.uploaded += other.uploaded;
    }
}

/// Counts by age group, then `ALL`.
type Groups = [Counts; ALL + 1];
/// Counts by day, bucket and configuration id.
type Days = BTreeMap<i64, BTreeMap<String, BTreeMap<String, Groups>>>;

/// The requests counted for analytics configurations, until they're exported.
#[derive(Debug, Default)]
pub(crate) struct Activity {
    days: Mutex<Days>,
}

impl Activity {
    /// Counts a request on `day` for a configuration, in its object's age group if it
    /// has one, and in `ALL`.
    pub(crate) fn add(
        &self,
        day: i64,
        (bucket, id): (&str, &str),
        group: Option<usize>,
        counts: Counts,
    ) {
        let mut days = self.days.lock().unwrap_or_else(PoisonError::into_inner);
        let groups = days
            .entry(day)
            .or_default()
            .entry(bucket.to_owned())
            .or_default()
            .entry(id.to_owned())
            .or_insert_with(|| [Counts::default(); ALL + 1]);
        if let Some(group) = group {
            groups[group].add(counts);
        }
        groups[ALL].add(counts);
    }

    fn of(&self, day: i64, bucket: &str, id: &str) -> Groups {
        let days = self.days.lock().unwrap_or_else(PoisonError::into_inner);
        days.get(&day)
            .and_then(|buckets| buckets.get(bucket))
            .and_then(|ids| ids.get(id))
            .copied()
            .unwrap_or_default()
    }

    /// A day's counts in `ALL` for a configuration.
    #[cfg(test)]
    pub(crate) fn of_for_test(&self, day: i64, bucket: &str, id: &str) -> Counts {
        self.of(day, bucket, id)[ALL]
    }

    fn snapshot(&self) -> Days {
        self.days
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Adds counts kept before a restart.
    fn restore(&self, kept: Days) {
        let mut days = self.days.lock().unwrap_or_else(PoisonError::into_inner);
        for (day, buckets) in kept {
            for (bucket, ids) in buckets {
                for (id, kept) in ids {
                    let groups = days
                        .entry(day)
                        .or_default()
                        .entry(bucket.clone())
                        .or_default()
                        .entry(id)
                        .or_insert_with(|| [Counts::default(); ALL + 1]);
                    for (group, kept) in groups.iter_mut().zip(kept) {
                        group.add(kept);
                    }
                }
            }
        }
    }

    /// Forgets the days before `first`.
    fn forget_before(&self, first: i64) {
        let mut days = self.days.lock().unwrap_or_else(PoisonError::into_inner);
        *days = days.split_off(&first);
    }
}

/// When each bucket's configurations last exported: the day of each, by bucket and id.
type Done = BTreeMap<String, BTreeMap<String, i64>>;

/// Exports each day's figures once it's over; the server runs it.
#[derive(Debug)]
pub(crate) struct Worker {
    drive: Drive,
    store: Store,
    activity: Arc<Activity>,
    page: usize,
}

impl Worker {
    pub(crate) fn new(drive: Drive, store: Store, activity: Arc<Activity>) -> Self {
        Self {
            drive,
            store,
            activity,
            page: PAGE,
        }
    }

    /// Exports the figures of each day that ends, and keeps the counts, until
    /// `stopping`.
    pub(crate) async fn run(self, stopping: CancellationToken) {
        self.activity.restore(self.kept_activity().await);
        let mut kept = self.activity.snapshot();
        let mut tick = tokio::time::interval(inventory::check_every(self.store.day_ms()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stopping.cancelled() => break,
                _ = tick.tick() => {
                    self.export_due(&stopping).await;
                    kept = self.keep_activity(kept).await;
                }
            }
        }
        self.keep_activity(kept).await;
    }

    /// Exports the day before today for each configuration that exports and hasn't: a
    /// new configuration's first export is of its first whole day.
    async fn export_due(&self, stopping: &CancellationToken) {
        let today = inventory::now_ms().div_euclid(self.store.day_ms());
        let done: Done = self.note(NOTE).await;
        let buckets = match self.store.list_buckets().await {
            Ok(buckets) => buckets,
            Err(err) => {
                tracing::warn!(error = %err, "couldn't list the buckets for their analytics exports");
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
                    tracing::warn!(bucket, error = %err, "couldn't read the bucket's analytics configurations");
                    if let Some(last) = last {
                        next.insert(bucket, last.clone());
                    }
                    continue;
                }
            };
            for (id, config) in configurations
                .analytics
                .iter()
                .filter(|(_, c)| c.export.is_some())
            {
                let exported = match last.and_then(|last| last.get(id)).copied() {
                    None => today - 1,
                    Some(last) if last >= today - 1 => last,
                    Some(last) => {
                        self.export((&bucket, id, config), today - 1, last, stopping)
                            .await
                    }
                };
                next.entry(bucket.clone())
                    .or_default()
                    .insert(id.clone(), exported);
            }
        }
        if next != done {
            self.set_note(NOTE, &next).await;
        }
        self.activity.forget_before(today - DAYS_KEPT);
    }

    /// Exports a day's figures, and says which day was last exported: this one, unless
    /// it may yet be (then `last`).
    async fn export(
        &self,
        (bucket, id, config): (&str, &str, &AnalyticsConfig),
        day: i64,
        last: i64,
        stopping: &CancellationToken,
    ) -> i64 {
        match self.write(bucket, id, config, day, stopping).await {
            Ok(()) => day,
            Err(Undelivered::Refused(why)) => {
                tracing::warn!(bucket, id, why, "an analytics export wasn't delivered");
                day
            }
            Err(Undelivered::Failed(why)) => {
                tracing::warn!(
                    bucket,
                    id,
                    why,
                    "an analytics export wasn't delivered; will try again"
                );
                last
            }
        }
    }

    /// Adds the day's rows to the configuration's export.
    async fn write(
        &self,
        bucket: &str,
        id: &str,
        config: &AnalyticsConfig,
        day: i64,
        stopping: &CancellationToken,
    ) -> Result<(), Undelivered> {
        let Some(export) = &config.export else {
            return Ok(());
        };
        let day_ms = self.store.day_ms();
        let stored = self
            .stored(bucket, config, (day + 1) * day_ms, stopping)
            .await?;
        let date = date(inventory::now_ms());
        let rows = rows(&date, id, &stored, &self.activity.of(day, bucket, id));
        let key = match export.prefix.as_deref().map(|p| p.trim_end_matches('/')) {
            Some(prefix) if !prefix.is_empty() => format!("{prefix}/{bucket}/{id}.csv"),
            _ => format!("{bucket}/{id}.csv"),
        };
        let earlier = self.earlier(&export.bucket, &key).await?;
        let delivery = Delivery {
            service: inventory::SERVICE,
            source: bucket,
            target: &export.bucket,
            content_type: "text/csv",
            canned_acl: Some("bucket-owner-full-control"),
            acl: None,
            encryption: None,
        };
        self.drive
            .deliver(&delivery, &key, Bytes::from(merge(&earlier, &rows)))
            .await?;
        Ok(())
    }

    /// What the configuration's objects stored at `at_ms`, by age group then `ALL`:
    /// objects and bytes.
    async fn stored(
        &self,
        bucket: &str,
        config: &AnalyticsConfig,
        at_ms: i64,
        stopping: &CancellationToken,
    ) -> Result<[(u64, u64); ALL + 1], Undelivered> {
        let store_error = |err| Undelivered::from(from_store(err));
        let day_ms = self.store.day_ms();
        let prefix = config
            .filter
            .as_ref()
            .and_then(|filter| filter.prefix.clone())
            .unwrap_or_default();
        let mut stored = [(0, 0); ALL + 1];
        let mut after: Option<After> = None;
        loop {
            if stopping.is_cancelled() {
                return Err(Undelivered::Failed("the server is stopping".to_owned()));
            }
            let query = ListQuery {
                prefix: prefix.clone(),
                delimiter: None,
                after: after.take(),
                max_keys: self.page,
            };
            let listing = self.store.list(bucket, query).await.map_err(store_error)?;
            for info in listing.objects.iter().filter(|info| matches(config, info)) {
                let age = (at_ms - ms(info)).div_euclid(day_ms);
                if let Some(group) = group(age, info.size) {
                    stored[group].0 += 1;
                    stored[group].1 += info.size;
                }
                stored[ALL].0 += 1;
                stored[ALL].1 += info.size;
            }
            match listing.next.filter(|_| listing.truncated) {
                Some(next) => after = Some(next),
                None => return Ok(stored),
            }
        }
    }

    /// The export so far, if there's one.
    async fn earlier(&self, bucket: &str, key: &str) -> Result<String, Undelivered> {
        let failed = |err: std::io::Error| Undelivered::Failed(err.to_string());
        let body = match self.store.read(bucket, key).await {
            Ok((_, Some(body))) => body,
            Ok((_, None)) | Err(StoreError::NoSuchKey | StoreError::NoSuchBucket) => {
                return Ok(String::new());
            }
            Err(err) => return Err(Undelivered::from(from_store(err))),
        };
        let mut text = String::new();
        let mut reader = body
            .all()
            .await
            .map_err(|err| Undelivered::from(from_store(err)))?;
        reader.read_to_string(&mut text).await.map_err(failed)?;
        Ok(text)
    }

    async fn note<T: serde::de::DeserializeOwned + Default>(&self, name: &str) -> T {
        match self.store.note(name).await {
            Ok(Some(note)) => serde_json::from_str(&note).unwrap_or_default(),
            Ok(None) => T::default(),
            Err(err) => {
                tracing::warn!(error = %err, note = name, "couldn't read what analytics exports kept");
                T::default()
            }
        }
    }

    async fn set_note<T: Serialize>(&self, name: &str, value: &T) {
        let note = serde_json::to_string(value)
            .ok()
            .filter(|note| note != "{}");
        if let Err(err) = self.store.set_note(name, note).await {
            tracing::warn!(error = %err, note = name, "couldn't keep what analytics exports need");
        }
    }

    async fn kept_activity(&self) -> Days {
        self.note(ACTIVITY_NOTE).await
    }

    /// Keeps the counts with the drive when they changed since `kept`.
    async fn keep_activity(&self, kept: Days) -> Days {
        let now = self.activity.snapshot();
        if now != kept {
            self.set_note(ACTIVITY_NOTE, &now).await;
        }
        now
    }
}

/// Whether the configuration analyses the object.
pub(crate) fn matches(config: &AnalyticsConfig, info: &ObjectInfo) -> bool {
    config
        .filter
        .as_ref()
        .is_none_or(|filter| filter.matches(&info.key, &info.attrs.tags))
}

/// When the object was last written, in ms since the epoch.
pub(crate) fn ms(info: &ObjectInfo) -> i64 {
    info.modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// `MM-DD-YYYY`.
fn date(ms: i64) -> String {
    let iso = crate::inventory::iso(ms);
    format!("{}-{}-{}", &iso[5..7], &iso[8..10], &iso[..4])
}

/// Megabytes, to six places at most.
fn mb(bytes: u64) -> String {
    #[expect(clippy::cast_precision_loss, reason = "a figure in a report")]
    let mb = bytes as f64 / MB;
    decimal(mb)
}

fn decimal(value: f64) -> String {
    let text = format!("{value:.6}");
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// What each age group stored: objects and bytes, then `ALL`'s.
type Stored = [(u64, u64); ALL + 1];

/// A day's rows: each age group's, then `ALL`.
fn rows(date: &str, id: &str, stored: &Stored, counts: &Groups) -> Vec<String> {
    (0..=ALL)
        .map(|group| {
            let name = GROUPS.get(group).map_or("ALL", |(_, name)| *name);
            let (objects, bytes) = stored[group];
            let day = counts[group];
            // The object count and uploads are only `ALL`'s, as on S3.
            let totals = if group == ALL {
                format!("{objects},{}", mb(day.uploaded))
            } else {
                ",".to_owned()
            };
            format!(
                "{date},{id},,STANDARD,{name},{totals},{},{},{},{},,",
                mb(bytes),
                mb(day.retrieved),
                day.requests,
                access_ratio(stored, counts, group),
            )
        })
        .collect()
}

/// The bytes retrieved over the bytes stored, for this age group and every older one
/// (`ALL`: every object); empty when nothing is stored.
fn access_ratio(stored: &Stored, counts: &Groups, group: usize) -> String {
    let groups = if group == ALL {
        ALL..=ALL
    } else {
        group..=ALL - 1
    };
    let retrieved: u64 = groups.clone().map(|g| counts[g].retrieved).sum();
    let bytes: u64 = groups.map(|g| stored[g].1).sum();
    if bytes == 0 {
        return String::new();
    }
    #[expect(clippy::cast_precision_loss, reason = "a figure in a report")]
    let ratio = retrieved as f64 / bytes as f64;
    decimal(ratio)
}

/// The export with the day's rows added: the header, then every row sorted by date
/// within age group, `ALL` last.
fn merge(earlier: &str, rows: &[String]) -> Vec<u8> {
    let mut all: Vec<&str> = earlier
        .lines()
        .filter(|line| !line.is_empty() && *line != HEADER)
        .chain(rows.iter().map(String::as_str))
        .collect();
    // Stable: a day's rows keep the order they were added in.
    all.sort_by_key(|row| order(row));
    let mut out =
        String::with_capacity(HEADER.len() + all.iter().map(|r| r.len() + 1).sum::<usize>() + 1);
    out.push_str(HEADER);
    out.push('\n');
    for row in all {
        out.push_str(row);
        out.push('\n');
    }
    out.into_bytes()
}

/// Where a row sorts: its age group (`ALL` after every group, anything else last), then
/// its date as `YYYYMMDD`.
fn order(row: &str) -> (usize, String) {
    let mut columns = row.split(',');
    let date = columns.next().unwrap_or_default();
    let age = columns.nth(3).unwrap_or_default();
    let group = GROUPS
        .iter()
        .position(|(_, name)| *name == age)
        .unwrap_or(if age == "ALL" { ALL } else { ALL + 1 });
    let sortable = match (date.get(6..10), date.get(0..2), date.get(3..5)) {
        (Some(year), Some(month), Some(day)) => format!("{year}{month}{day}"),
        _ => String::new(),
    };
    (group, sortable)
}

#[cfg(test)]
mod tests {
    use teifs_store::Layout;
    use teifs_types::{
        ObjectAttrs,
        configs::{AnalyticsExport, Filter},
    };

    use super::*;

    #[test]
    fn objects_from_128_kib_are_grouped_by_age() {
        assert_eq!(group(0, MIN_AGED - 1), None);
        for (age, expected) in [
            (0, 0),
            (14, 0),
            (15, 1),
            (89, 5),
            (90, 6),
            (364, 9),
            (365, 10),
            (729, 10),
            (730, 11),
            (5000, 11),
        ] {
            assert_eq!(group(age, MIN_AGED), Some(expected), "{age}");
        }
        // A clock that went back still finds a group.
        assert_eq!(group(-1, MIN_AGED), Some(0));
    }

    fn day_counts() -> Groups {
        let mut counts = [Counts::default(); ALL + 1];
        counts[0] = Counts {
            requests: 3,
            retrieved: 1024 * 1024,
            uploaded: 0,
        };
        counts[11] = Counts {
            requests: 1,
            retrieved: 512 * 1024,
            uploaded: 0,
        };
        counts[ALL] = Counts {
            requests: 5,
            retrieved: 1536 * 1024 + 10,
            uploaded: 2 * 1024 * 1024,
        };
        counts
    }

    #[test]
    fn a_days_rows_are_s3s_columns() {
        let mut stored = [(0, 0); ALL + 1];
        stored[0] = (2, 4 * 1024 * 1024);
        stored[11] = (1, 1024 * 1024);
        stored[ALL] = (4, 5 * 1024 * 1024 + 10);
        let made = rows("10-01-2026", "docs", &stored, &day_counts());
        assert_eq!(made.len(), 13);
        assert_eq!(made[0], "10-01-2026,docs,,STANDARD,000-014,,,4,1,3,0.3,,");
        assert_eq!(made[1], "10-01-2026,docs,,STANDARD,015-029,,,0,0,0,0.5,,");
        assert_eq!(made[11], "10-01-2026,docs,,STANDARD,730+,,,1,0.5,1,0.5,,");
        assert_eq!(
            made[ALL],
            "10-01-2026,docs,,STANDARD,ALL,4,2,5.00001,1.50001,5,0.300001,,"
        );
        // Nothing stored: no ratio.
        let empty = rows("10-01-2026", "docs", &[(0, 0); ALL + 1], &day_counts());
        assert_eq!(empty[11], "10-01-2026,docs,,STANDARD,730+,,,0,0.5,1,,,");
        assert_eq!(made[0].split(',').count(), HEADER.split(',').count());
    }

    #[test]
    fn exports_sort_by_date_within_age_group() {
        let first = rows("09-30-2026", "a", &[(0, 0); ALL + 1], &day_counts());
        let earlier = String::from_utf8(merge("", &first)).unwrap();
        assert!(earlier.starts_with(&format!("{HEADER}\n09-30-2026,a,,STANDARD,000-014,")));
        let second = rows("10-01-2026", "a", &[(0, 0); ALL + 1], &day_counts());
        let both = String::from_utf8(merge(&earlier, &second)).unwrap();
        let lines: Vec<&str> = both.lines().collect();
        assert_eq!(lines.len(), 1 + 26);
        assert_eq!(lines[0], HEADER);
        let order: Vec<(&str, &str)> = lines[1..]
            .iter()
            .map(|line| {
                let columns: Vec<&str> = line.split(',').collect();
                (columns[4], columns[0])
            })
            .collect();
        assert_eq!(
            &order[..2],
            [("000-014", "09-30-2026"), ("000-014", "10-01-2026")]
        );
        assert_eq!(&order[24..], [("ALL", "09-30-2026"), ("ALL", "10-01-2026")]);
        // Years sort before months.
        assert!(order_of("12-31-2025") < order_of("01-01-2026"));
        assert!(both.ends_with('\n'));
    }

    fn order_of(date: &str) -> (usize, String) {
        order(&format!("{date},a,,STANDARD,ALL,"))
    }

    #[test]
    fn activity_is_added_kept_and_forgotten() {
        let activity = Activity::default();
        let one = Counts {
            requests: 1,
            retrieved: 5,
            uploaded: 0,
        };
        activity.add(10, ("b", "x"), Some(2), one);
        activity.add(10, ("b", "x"), None, one);
        let day = activity.of(10, "b", "x");
        assert_eq!(
            (day[2].requests, day[ALL].requests, day[ALL].retrieved),
            (1, 2, 10)
        );
        assert_eq!(activity.of(10, "b", "y"), [Counts::default(); ALL + 1]);
        let kept = activity.snapshot();
        let restored = Activity::default();
        restored.add(10, ("b", "x"), None, one);
        restored.restore(kept);
        assert_eq!(restored.of(10, "b", "x")[ALL].requests, 3);
        activity.add(12, ("b", "x"), None, one);
        activity.forget_before(11);
        assert_eq!(activity.of(10, "b", "x")[ALL].requests, 0);
        assert_eq!(activity.of(12, "b", "x")[ALL].requests, 1);
    }

    /// A drive with `src` (a large and a small object under `docs/`, one elsewhere) and
    /// `dst`, folder buckets, and a worker for it.
    async fn setup() -> (tempfile::TempDir, Worker) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for bucket in ["src", "dst"] {
            store.create_bucket(bucket, Layout::Folder).await.unwrap();
        }
        for (key, size) in [
            ("docs/big", MIN_AGED),
            ("docs/small", 10),
            ("other", MIN_AGED),
        ] {
            let data = vec![0; usize::try_from(size).unwrap()];
            store
                .put_bytes("src", key, &data, ObjectAttrs::default())
                .await
                .unwrap();
        }
        let notifier = Arc::new(teifs_notify::Notifier::none());
        let drive = Drive::new(store.clone(), Layout::Folder, false, notifier, None);
        let worker = Worker {
            drive,
            store,
            activity: Arc::new(Activity::default()),
            page: 1,
        };
        (dir, worker)
    }

    fn config(prefix: Option<&str>) -> AnalyticsConfig {
        AnalyticsConfig {
            filter: Some(Filter {
                prefix: Some("docs/".to_owned()),
                ..Filter::default()
            }),
            export: Some(AnalyticsExport {
                bucket: "dst".to_owned(),
                account: None,
                prefix: prefix.map(str::to_owned),
            }),
        }
    }

    async fn export(worker: &Worker, key: &str) -> Vec<String> {
        let (_, body) = worker.store.read("dst", key).await.unwrap();
        let mut text = String::new();
        body.unwrap()
            .all()
            .await
            .unwrap()
            .read_to_string(&mut text)
            .await
            .unwrap();
        text.lines().map(str::to_owned).collect()
    }

    #[tokio::test]
    async fn a_days_figures_are_added_to_the_export() {
        let (_dir, worker) = setup().await;
        let stop = CancellationToken::new();
        let day = inventory::now_ms().div_euclid(worker.store.day_ms());
        let get = Counts {
            requests: 1,
            retrieved: 1024 * 1024,
            uploaded: 0,
        };
        worker.activity.add(day, ("src", "docs"), Some(0), get);
        worker
            .write("src", "docs", &config(Some("an/")), day, &stop)
            .await
            .unwrap();
        let lines = export(&worker, "an/src/docs.csv").await;
        assert_eq!(lines.len(), 14);
        assert_eq!(lines[0], HEADER);
        let date = date(inventory::now_ms());
        assert_eq!(
            lines[1],
            format!("{date},docs,,STANDARD,000-014,,,0.125,1,1,8,,")
        );
        // Both objects under docs/, the small one only in ALL.
        assert_eq!(
            lines[13],
            format!("{date},docs,,STANDARD,ALL,2,0,0.12501,1,1,7.99939,,")
        );
        // The next day's are added.
        worker
            .write("src", "docs", &config(Some("an/")), day + 1, &stop)
            .await
            .unwrap();
        let lines = export(&worker, "an/src/docs.csv").await;
        assert_eq!(lines.len(), 27);
        assert_eq!(
            lines[2],
            format!("{date},docs,,STANDARD,000-014,,,0.125,0,0,0,,")
        );
        // Without a prefix it's at the destination's top.
        worker
            .write("src", "docs", &config(None), day, &stop)
            .await
            .unwrap();
        assert_eq!(export(&worker, "src/docs.csv").await.len(), 14);
        // A bucket that's gone can't be exported to, and says so.
        let mut gone = config(None);
        gone.export.as_mut().unwrap().bucket = "gone".to_owned();
        assert!(
            worker
                .write("src", "docs", &gone, day, &stop)
                .await
                .is_err()
        );
        // A refused export isn't tried again; one that failed is, from the last day.
        let task = ("src", "docs", &gone);
        assert_eq!(worker.export(task, day, day - 5, &stop).await, day);
        stop.cancel();
        assert!(matches!(
            worker.write("src", "docs", &config(None), day, &stop).await,
            Err(Undelivered::Failed(_))
        ));
        let task = ("src", "docs", &config(None));
        assert_eq!(worker.export(task, day, day - 5, &stop).await, day - 5);
    }

    #[tokio::test]
    async fn each_configuration_exports_each_whole_day_once() {
        let (_dir, worker) = setup().await;
        let stop = CancellationToken::new();
        let configurations = teifs_types::configs::Configurations {
            analytics: [
                ("docs".to_owned(), config(None)),
                (
                    "kept".to_owned(),
                    AnalyticsConfig {
                        filter: None,
                        export: None,
                    },
                ),
            ]
            .into(),
            ..Default::default()
        };
        worker
            .store
            .set_bucket_configurations("src", configurations)
            .await
            .unwrap();
        let today = inventory::now_ms().div_euclid(worker.store.day_ms());
        let one = Counts {
            requests: 1,
            retrieved: 0,
            uploaded: 0,
        };
        worker
            .activity
            .add(today - DAYS_KEPT - 1, ("src", "docs"), None, one);
        worker
            .activity
            .add(today - DAYS_KEPT, ("src", "docs"), None, one);
        // A new configuration's first export is of its first whole day.
        worker.export_due(&stop).await;
        // Counts too old to be exported are forgotten.
        let kept: Vec<i64> = worker.activity.snapshot().into_keys().collect();
        assert_eq!(kept, [today - DAYS_KEPT]);
        let done: Done = worker.note(NOTE).await;
        assert_eq!(done["src"].get("docs"), Some(&(today - 1)));
        assert!(!done["src"].contains_key("kept"));
        assert!(worker.store.read("dst", "src/docs.csv").await.is_err());
        // A day not yet exported is.
        worker
            .set_note(
                NOTE,
                &Done::from([("src".to_owned(), [("docs".to_owned(), today - 2)].into())]),
            )
            .await;
        worker.export_due(&stop).await;
        assert_eq!(export(&worker, "src/docs.csv").await.len(), 14);
        let done: Done = worker.note(NOTE).await;
        assert_eq!(done["src"]["docs"], today - 1);
        // Once.
        worker.export_due(&stop).await;
        assert_eq!(export(&worker, "src/docs.csv").await.len(), 14);
    }

    #[tokio::test]
    async fn counts_are_kept_through_a_restart() {
        let (_dir, worker) = setup().await;
        let one = Counts {
            requests: 1,
            retrieved: 0,
            uploaded: 0,
        };
        worker.activity.add(5, ("src", "docs"), None, one);
        let kept = worker.keep_activity(Days::new()).await;
        assert_eq!(kept, worker.activity.snapshot());
        let again = Worker {
            activity: Arc::new(Activity::default()),
            ..worker
        };
        again.activity.restore(again.kept_activity().await);
        assert_eq!(again.activity.of(5, "src", "docs")[ALL].requests, 1);
    }

    #[tokio::test]
    async fn counts_are_kept_when_the_worker_stops() {
        let (_dir, worker) = setup().await;
        let store = worker.store.clone();
        let activity = Arc::clone(&worker.activity);
        let stop = CancellationToken::new();
        let running = tokio::spawn(worker.run(stop.clone()));
        // After the first check, the next is a quarter of an hour away.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let one = Counts {
            requests: 1,
            retrieved: 0,
            uploaded: 0,
        };
        activity.add(7, ("src", "docs"), None, one);
        stop.cancel();
        running.await.unwrap();
        let note = store.note(ACTIVITY_NOTE).await.unwrap().unwrap();
        let kept: Days = serde_json::from_str(&note).unwrap();
        assert_eq!(kept[&7]["src"]["docs"][ALL].requests, 1);
    }
}
