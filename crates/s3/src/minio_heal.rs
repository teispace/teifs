//! `MinIO`'s heal (`POST /minio/admin/v3/heal/{bucket}/{prefix}`, `mc admin heal`) and
//! its background heal's status (`POST /minio/admin/v3/background-heal/status`).
//!
//! A heal sequence goes through the buckets, or one bucket's objects under a prefix,
//! and reports each as a `madmin.HealResultItem`, which the caller collects by polling
//! with the sequence's token, as `MinIO`'s do. A drive keeps one copy, so there's no
//! other to heal from: a sequence checks and reports, and changes nothing. A normal scan
//! reads each version's metadata; a deep one (`--scan deep`) reads its bytes and
//! compares them with what was recorded, as `teifs verify` does.
//!
//! The background heal is the drive's scrub: its status counts what the scrub checked.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use http::StatusCode;
use s3s::{Body, S3Error, S3Request, S3Response, S3Result};
use serde::{Deserialize, Serialize};
use teifs_store::{Store, StoreError, Verdict, VersionsQuery};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;

use crate::{
    admin::{error, json},
    errors::StoreResultExt,
    minio_info,
    routes::{Routes, s3_refusal, signed_body},
};

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `POST heal/{bucket}/{prefix}`.
    Heal,
    /// `POST background-heal/status`.
    BackgroundStatus,
}

impl Call {
    /// The call's name, as the audit log and traces name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Heal => "Heal",
            Self::BackgroundStatus => "BackgroundHealStatus",
        }
    }

    pub(crate) async fn call(
        self,
        routes: &Routes,
        req: S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        match self {
            Self::Heal => heal(routes, req).await,
            Self::BackgroundStatus => background_status(routes, &req).await,
        }
    }
}

/// The most results a sequence holds for its caller before it waits for them to be read.
const MAX_UNREAD: usize = 1000;
/// How long a sequence waits for its caller to read its results before it gives up.
const UNREAD_TIMEOUT: Duration = Duration::from_hours(24);
/// How long a sequence's results are kept once it has ended.
const KEPT: Duration = Duration::from_mins(10);
/// The largest heal settings document read.
const MAX_SETTINGS: usize = 64 * 1024;
/// Versions listed at a time.
const PAGE: usize = 1000;
/// `madmin.HealDeepScan`.
const DEEP_SCAN: u8 = 2;

/// What a heal is asked to do (`madmin.HealOpts`), echoed back in its status.
#[expect(clippy::struct_excessive_bools, reason = "madmin.HealOpts' fields")]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Settings {
    recursive: bool,
    dry_run: bool,
    remove: bool,
    recreate: bool,
    scan_mode: u8,
    update_parity: bool,
    #[serde(rename = "nolock")]
    no_lock: bool,
}

/// `madmin.HealDriveInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DriveInfo {
    uuid: String,
    endpoint: String,
    state: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Drives {
    drives: Vec<DriveInfo>,
}

/// `madmin.HealResultItem`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    #[serde(rename = "resultId")]
    result_index: u64,
    #[serde(rename = "type")]
    kind: &'static str,
    bucket: String,
    object: String,
    version_id: String,
    detail: String,
    disk_count: u32,
    set_count: u32,
    before: Drives,
    after: Drives,
    object_size: u64,
}

/// `madmin.HealStartSuccess`, and `HealStopSuccess`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Started<'a> {
    client_token: &'a str,
    client_address: &'a str,
    start_time: &'a str,
}

/// `MinIO`'s heal sequence status (`madmin.HealTaskStatus`).
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Status<'a> {
    summary: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    detail: &'a str,
    start_time: &'a str,
    settings: &'a Settings,
    items: Vec<Item>,
}

/// Where a sequence is.
#[derive(Debug, Default)]
struct Progress {
    summary: &'static str,
    detail: String,
    /// The results its caller hasn't read yet.
    unread: Vec<Item>,
    /// The last result's index.
    last: u64,
    ended: Option<Instant>,
}

/// One heal sequence.
#[derive(Debug)]
struct Sequence {
    token: String,
    client: String,
    started: String,
    settings: Settings,
    stop: CancellationToken,
    progress: Mutex<Progress>,
}

impl Sequence {
    fn progress(&self) -> std::sync::MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ended(&self) -> bool {
        self.progress().ended.is_some()
    }

    fn started(&self) -> Vec<u8> {
        serde_json::to_vec(&Started {
            client_token: &self.token,
            client_address: &self.client,
            start_time: &self.started,
        })
        .expect("a heal start serializes")
    }

    /// Its status with the results not read yet, which are then read.
    fn status(&self) -> Vec<u8> {
        let mut progress = self.progress();
        let items = std::mem::take(&mut progress.unread);
        serde_json::to_vec(&Status {
            summary: progress.summary,
            detail: &progress.detail,
            start_time: &self.started,
            settings: &self.settings,
            items,
        })
        .expect("a heal status serializes")
    }

    /// Adds a result once its caller has room for it.
    async fn report(&self, mut item: Item) -> Result<(), Ended> {
        let gave_up = tokio::time::Instant::now() + UNREAD_TIMEOUT;
        loop {
            {
                let mut progress = self.progress();
                if progress.unread.len() < MAX_UNREAD {
                    progress.last += 1;
                    item.result_index = progress.last;
                    progress.unread.push(item);
                    return Ok(());
                }
            }
            tokio::select! {
                () = self.stop.cancelled() => return Err(Ended::Stopped),
                () = tokio::time::sleep_until(gave_up) => {
                    return Err(Ended::Failed(
                        "the heal's results weren't read for too long".to_owned(),
                    ));
                }
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }
}

/// Why a sequence ended early.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Stopped,
    Failed(String),
}

/// The heal sequences, by the path they heal.
#[derive(Debug, Default)]
pub(crate) struct Heals {
    sequences: Mutex<HashMap<String, Arc<Sequence>>>,
}

impl Heals {
    fn sequences(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Sequence>>> {
        let mut sequences = self
            .sequences
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        sequences.retain(|_, sequence| {
            sequence
                .progress()
                .ended
                .is_none_or(|ended| ended.elapsed() < KEPT)
        });
        sequences
    }

    fn get(&self, path: &str) -> Option<Arc<Sequence>> {
        self.sequences().get(path).cloned()
    }

    /// Stops the sequence on `path`, as `MinIO`'s `stopHealSequence` does.
    async fn stop(&self, path: &str) -> Vec<u8> {
        let Some(sequence) = self.get(path) else {
            let now = rfc3339(OffsetDateTime::now_utc());
            return serde_json::to_vec(&Started {
                client_token: "unknown",
                client_address: "",
                start_time: &now,
            })
            .expect("a heal stop serializes");
        };
        sequence.stop.cancel();
        while !sequence.ended() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.sequences().remove(path);
        sequence.started()
    }

    /// Starts a sequence on `path`, unless one runs on it or on a path inside or around it.
    fn launch(&self, path: &str, sequence: &Arc<Sequence>) -> S3Result<()> {
        let mut sequences = self.sequences();
        if let Some(running) = sequences.get(path).filter(|s| !s.ended()) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "XMinioHealAlreadyRunning",
                format!(
                    "Heal is already running on the given path (use force-start option to \
                     stop and start afresh). The heal was started by IP {} at {}, token is {}",
                    running.client, running.started, running.token
                ),
            ));
        }
        if let Some(other) = sequences
            .iter()
            .find(|(other, s)| !s.ended() && (other.starts_with(path) || path.starts_with(*other)))
            .map(|(other, _)| other)
        {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "XMinioHealOverlappingPaths",
                format!(
                    "The provided heal sequence path overlaps with an existing heal path: {other}"
                ),
            ));
        }
        sequences.insert(path.to_owned(), Arc::clone(sequence));
        Ok(())
    }
}

/// A time as `MinIO` writes one.
fn rfc3339(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_default()
}

/// What a heal request names and asks.
#[derive(Debug, PartialEq, Eq)]
struct Asked {
    bucket: String,
    prefix: String,
    token: Option<String>,
    force_start: bool,
    force_stop: bool,
}

impl Asked {
    /// Reads the path after `heal/` and the query, as `MinIO`'s `extractHealInitParams`.
    fn parse(path: &str, query: &str) -> S3Result<Self> {
        let rest = path.split_once("/heal/").map_or("", |(_, rest)| rest);
        let rest = percent_encoding::percent_decode_str(rest)
            .decode_utf8()
            .map_err(|_| invalid("InvalidObjectName", "The path isn't UTF-8."))?;
        let (bucket, prefix) = rest.split_once('/').unwrap_or((&rest, ""));
        if bucket.is_empty() && !prefix.is_empty() {
            return Err(invalid(
                "XMinioHealMissingBucket",
                "A heal start request with a non-empty object-prefix parameter requires a \
                 bucket to be specified.",
            ));
        }
        let mut asked = Self {
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
            token: None,
            force_start: false,
            force_stop: false,
        };
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            match &*name {
                "clientToken" if asked.token.is_none() => asked.token = Some(value.into_owned()),
                "forceStart" => asked.force_start = true,
                "forceStop" => asked.force_stop = true,
                _ => {}
            }
        }
        if (asked.force_start && asked.force_stop)
            || (asked.token.is_some() && (asked.force_start || asked.force_stop))
        {
            return Err(invalid(
                "InvalidRequest",
                "Ask for a heal's status, or start or stop one: not two of them at once.",
            ));
        }
        Ok(asked)
    }

    /// The path the sequence heals, as `MinIO` keys sequences.
    fn path(&self) -> String {
        if self.prefix.is_empty() {
            self.bucket.clone()
        } else {
            format!("{}/{}", self.bucket, self.prefix)
        }
    }
}

fn invalid(code: &str, message: &str) -> S3Error {
    error(StatusCode::BAD_REQUEST, code, message)
}

/// `POST /minio/admin/v3/heal/{bucket}/{prefix}`.
async fn heal(routes: &Routes, mut req: S3Request<Body>) -> S3Result<S3Response<Body>> {
    let asked = Asked::parse(req.uri.path(), req.uri.query().unwrap_or_default())?;
    let settings = if asked.token.is_some() {
        Settings::default()
    } else {
        let body = signed_body(&mut req, MAX_SETTINGS)
            .await
            .map_err(s3_refusal)?;
        serde_json::from_slice(&body).map_err(|_| {
            invalid(
                "XMinioRequestBodyParse",
                "The request body failed to parse.",
            )
        })?
    };
    let path = asked.path();
    let heals = &routes.heals;
    if let Some(token) = &asked.token {
        let Some(sequence) = heals.get(&path) else {
            // Gone: it finished a while ago.
            return Ok(json(&serde_json::json!({ "Summary": "finished" })));
        };
        if *token != sequence.token {
            return Err(invalid(
                "XMinioHealInvalidClientToken",
                "Client token mismatch",
            ));
        }
        return Ok(answer(sequence.status()));
    }
    if asked.force_stop {
        return Ok(answer(heals.stop(&path).await));
    }
    if !asked.force_start
        && let Some(sequence) = heals.get(&path)
        && !sequence.ended()
        && !sequence.progress().unread.is_empty()
    {
        // Asked again without its token: the caller is told it.
        return Ok(answer(sequence.started()));
    }
    if !asked.bucket.is_empty() {
        routes.store.head_bucket(&asked.bucket).await.s3()?;
    }
    if asked.force_start {
        heals.stop(&path).await;
    }
    let client = req
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    let sequence = Arc::new(Sequence {
        token: uuid::Uuid::new_v4().to_string(),
        client,
        started: rfc3339(OffsetDateTime::now_utc()),
        settings,
        stop: CancellationToken::new(),
        progress: Mutex::new(Progress {
            summary: "running",
            ..Progress::default()
        }),
    });
    heals.launch(&path, &sequence)?;
    let drive = minio_info::disks(routes)
        .await
        .into_iter()
        .next()
        .map(|disk| disk.endpoint)
        .unwrap_or_default();
    let walk = Walk {
        store: routes.store.clone(),
        sequence: Arc::clone(&sequence),
        drive: (routes.store.format().drive.clone(), drive),
    };
    tokio::spawn(async move {
        let ended = walk.run(&asked.bucket, &asked.prefix).await;
        let mut progress = walk.sequence.progress();
        progress.summary = match ended {
            Ok(()) => "finished",
            Err(Ended::Stopped) => "stopped",
            Err(Ended::Failed(detail)) => {
                progress.detail = detail;
                "stopped"
            }
        };
        progress.ended = Some(Instant::now());
    });
    Ok(answer(sequence.started()))
}

fn answer(body: Vec<u8>) -> S3Response<Body> {
    let mut response = S3Response::new(Body::from(body));
    response.headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    response
}

/// A sequence going through the drive.
struct Walk {
    store: Store,
    sequence: Arc<Sequence>,
    /// The drive's id and where it is.
    drive: (String, String),
}

impl Walk {
    async fn run(&self, bucket: &str, prefix: &str) -> Result<(), Ended> {
        let buckets = if bucket.is_empty() {
            let mut buckets = self
                .store
                .list_buckets()
                .await
                .map_err(|err| failed(&err))?;
            // Newest first, as MinIO heals them.
            buckets.sort_by_key(|b| std::cmp::Reverse(b.created));
            buckets.into_iter().map(|b| b.name).collect()
        } else {
            vec![bucket.to_owned()]
        };
        for bucket in buckets {
            if self.sequence.stop.is_cancelled() {
                return Err(Ended::Stopped);
            }
            self.sequence
                .report(self.item("bucket", &bucket, ("", ""), ("ok", String::new()), 0))
                .await?;
            self.objects(&bucket, prefix).await?;
        }
        Ok(())
    }

    /// Checks the versions under `prefix`: all of them when the heal is recursive, else
    /// only the keys right under it.
    async fn objects(&self, bucket: &str, prefix: &str) -> Result<(), Ended> {
        let mut next: Option<(String, Option<String>)> = None;
        loop {
            let (key_marker, version_marker) = next.take().unzip();
            let query = VersionsQuery {
                prefix: prefix.to_owned(),
                delimiter: (!self.sequence.settings.recursive).then(|| "/".to_owned()),
                key_marker,
                version_marker: version_marker.flatten(),
                max_keys: PAGE,
            };
            let listing = match self.store.list_versions(bucket, query).await {
                Ok(listing) => listing,
                // Removed meanwhile.
                Err(StoreError::NoSuchBucket) => return Ok(()),
                Err(err) => return Err(failed(&err)),
            };
            for version in listing.versions {
                if self.sequence.stop.is_cancelled() {
                    return Err(Ended::Stopped);
                }
                if version.delete_marker {
                    continue;
                }
                let info = version.info;
                let version_id = info.version_id.unwrap_or_default();
                let Some(state) = self.check(bucket, &info.key, &version_id).await? else {
                    continue;
                };
                let shown = if version_id == "null" {
                    ""
                } else {
                    &version_id
                };
                let item = self.item("object", bucket, (&info.key, shown), state, info.size);
                self.sequence.report(item).await?;
            }
            if !listing.truncated {
                return Ok(());
            }
            next = listing.next;
            if next.is_none() {
                return Ok(());
            }
        }
    }

    /// A version's state on the drive and what's wrong with it; none when it's gone.
    async fn check(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<Option<(&'static str, String)>, Ended> {
        if self.sequence.settings.scan_mode == DEEP_SCAN {
            return match self
                .store
                .verify_version(bucket, key, Some(version_id))
                .await
            {
                Ok(verdict) => Ok(Some(verdict_state(&verdict))),
                Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => Ok(None),
                Err(err) => Err(failed(&err)),
            };
        }
        match self.store.head_version(bucket, key, Some(version_id)).await {
            Ok(_) => Ok(Some(("ok", String::new()))),
            Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => Ok(None),
            Err(StoreError::CorruptMetadata | StoreError::Crypto(_)) => {
                Ok(Some(("corrupt", "its metadata can't be read".to_owned())))
            }
            Err(StoreError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
                Ok(Some(("missing", "its metadata is missing".to_owned())))
            }
            Err(err) => Err(failed(&err)),
        }
    }

    fn item(
        &self,
        kind: &'static str,
        bucket: &str,
        (object, version_id): (&str, &str),
        (state, detail): (&'static str, String),
        size: u64,
    ) -> Item {
        let drives = Drives {
            drives: vec![DriveInfo {
                uuid: self.drive.0.clone(),
                endpoint: self.drive.1.clone(),
                state,
            }],
        };
        Item {
            result_index: 0,
            kind,
            bucket: bucket.to_owned(),
            object: object.to_owned(),
            version_id: version_id.to_owned(),
            detail,
            disk_count: 1,
            set_count: 1,
            // Nothing is changed: there's no other copy to heal from.
            after: drives.clone(),
            before: drives,
            object_size: size,
        }
    }
}

/// A check's verdict as a drive state (`madmin.DriveState…`) and what's wrong.
fn verdict_state(verdict: &Verdict) -> (&'static str, String) {
    match verdict {
        Verdict::Intact => ("ok", String::new()),
        Verdict::Damaged { damage } => {
            let state = if matches!(damage, teifs_store::Damage::Missing) {
                "missing"
            } else {
                "corrupt"
            };
            (state, damage.to_string())
        }
        Verdict::Unverifiable { reason } => ("ok", format!("not checked: {reason}")),
    }
}

fn failed(err: &StoreError) -> Ended {
    tracing::warn!(error = %err, "a heal stopped");
    Ended::Failed(err.to_string())
}

/// `madmin.BgHealState`: the background heal, which is the drive's scrub.
#[derive(Serialize)]
struct BackgroundHeal {
    offline_nodes: [&'static str; 0],
    #[serde(rename = "ScannedItemsCount")]
    scanned: u64,
    #[serde(rename = "HealDisks")]
    heal_disks: [&'static str; 0],
    sets: [SetStatus; 1],
    mrf: HashMap<String, Mrf>,
    sc_parity: HashMap<&'static str, u32>,
}

/// `madmin.SetStatus`.
#[derive(Serialize)]
struct SetStatus {
    id: &'static str,
    pool_index: u32,
    set_index: u32,
    heal_status: &'static str,
    heal_priority: &'static str,
    total_objects: u64,
    disks: Vec<minio_info::Disk>,
}

/// `madmin.MRFStatus`.
#[derive(Serialize)]
struct Mrf {
    bytes_healed: u64,
    items_healed: u64,
}

/// `POST /minio/admin/v3/background-heal/status`.
async fn background_status(routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let report = routes.store.scrub_report().await.s3()?;
    let scanned = report
        .current
        .as_ref()
        .or(report.last.as_ref())
        .map_or(0, |pass| pass.versions);
    let node = minio_info::endpoint(routes, req);
    Ok(json(&BackgroundHeal {
        offline_nodes: [],
        scanned,
        heal_disks: [],
        sets: [SetStatus {
            id: "0",
            pool_index: 0,
            set_index: 0,
            heal_status: if report.current.is_some() {
                "healing"
            } else {
                ""
            },
            heal_priority: "",
            total_objects: scanned,
            disks: minio_info::disks(routes).await,
        }],
        mrf: HashMap::from([(
            node,
            Mrf {
                bytes_healed: 0,
                items_healed: 0,
            },
        )]),
        sc_parity: HashMap::from([("STANDARD", 0)]),
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use teifs_store::{Damage, Unverifiable};

    use super::*;

    #[test]
    fn a_heal_request_is_read_as_minio_reads_it() {
        let asked = Asked::parse(
            "/minio/admin/v3/heal/pics/2026/a%20b",
            "clientToken=t1&clientToken=t2",
        )
        .unwrap();
        assert_eq!(
            asked,
            Asked {
                bucket: "pics".to_owned(),
                prefix: "2026/a b".to_owned(),
                token: Some("t1".to_owned()),
                force_start: false,
                force_stop: false,
            }
        );
        assert_eq!(asked.path(), "pics/2026/a b");
        let everything = Asked::parse("/minio/admin/v3/heal/", "forceStart=").unwrap();
        assert_eq!(
            (everything.path().as_str(), everything.force_start),
            ("", true)
        );

        for (path, query, code) in [
            ("/minio/admin/v3/heal//k", "", "XMinioHealMissingBucket"),
            (
                "/minio/admin/v3/heal/b",
                "forceStart&forceStop",
                "InvalidRequest",
            ),
            (
                "/minio/admin/v3/heal/b",
                "clientToken=t&forceStop",
                "InvalidRequest",
            ),
        ] {
            let err = Asked::parse(path, query).unwrap_err();
            assert_eq!(err.code().as_str(), code, "{path}?{query}");
        }
    }

    #[test]
    fn settings_are_madmin_s_heal_opts() {
        let settings: Settings = serde_json::from_str(
            r#"{"recursive":true,"dryRun":false,"remove":true,"recreate":false,
                "scanMode":2,"updateParity":false,"nolock":true,"pool":1}"#,
        )
        .unwrap();
        assert!(settings.recursive && settings.remove && settings.no_lock);
        assert_eq!(settings.scan_mode, DEEP_SCAN);
        let echoed = serde_json::to_value(&settings).unwrap();
        assert_eq!(echoed["dryRun"], false);
        assert_eq!(echoed["nolock"], true);
    }

    #[test]
    fn verdicts_are_drive_states() {
        assert_eq!(verdict_state(&Verdict::Intact), ("ok", String::new()));
        assert_eq!(
            verdict_state(&Damage::Missing.into()),
            ("missing", "its data is missing".to_owned())
        );
        assert_eq!(verdict_state(&Damage::Etag.into()).0, "corrupt");
        let (state, detail) = verdict_state(&Unverifiable::CustomerKey.into());
        assert_eq!(state, "ok");
        assert!(detail.starts_with("not checked: "), "{detail}");
    }

    fn sequence() -> Sequence {
        Sequence {
            token: "t".to_owned(),
            client: String::new(),
            started: "2026-10-02T10:00:00Z".to_owned(),
            settings: Settings::default(),
            stop: CancellationToken::new(),
            progress: Mutex::new(Progress {
                summary: "running",
                ..Progress::default()
            }),
        }
    }

    fn item(object: &str) -> Item {
        let drives = Drives { drives: Vec::new() };
        Item {
            result_index: 0,
            kind: "object",
            bucket: "b".to_owned(),
            object: object.to_owned(),
            version_id: String::new(),
            detail: String::new(),
            disk_count: 1,
            set_count: 1,
            before: drives.clone(),
            after: drives,
            object_size: 0,
        }
    }

    #[tokio::test]
    async fn results_are_numbered_and_read_once() {
        let sequence = sequence();
        sequence.report(item("a")).await.unwrap();
        sequence.report(item("b")).await.unwrap();
        let status: serde_json::Value = serde_json::from_slice(&sequence.status()).unwrap();
        assert_eq!(status["Summary"], "running");
        assert_eq!(status["StartTime"], "2026-10-02T10:00:00Z");
        let ids: Vec<_> = status["Items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    i["resultId"].as_u64().unwrap(),
                    i["object"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(ids, [(1, "a".to_owned()), (2, "b".to_owned())]);
        sequence.report(item("c")).await.unwrap();
        let status: serde_json::Value = serde_json::from_slice(&sequence.status()).unwrap();
        assert_eq!(status["Items"][0]["resultId"], 3);
        assert_eq!(status["Items"].as_array().unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_sequence_waits_for_its_caller_or_a_stop() {
        let sequence = Arc::new(sequence());
        for n in 0..MAX_UNREAD {
            sequence.report(item(&n.to_string())).await.unwrap();
        }
        let waiting = {
            let sequence = Arc::clone(&sequence);
            tokio::spawn(async move { sequence.report(item("next")).await })
        };
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!waiting.is_finished());
        sequence.status();
        assert_eq!(waiting.await.unwrap(), Ok(()));

        for n in 0..MAX_UNREAD - 1 {
            sequence.report(item(&n.to_string())).await.unwrap();
        }
        let stopped = {
            let sequence = Arc::clone(&sequence);
            tokio::spawn(async move { sequence.report(item("next")).await })
        };
        sequence.stop.cancel();
        assert_eq!(stopped.await.unwrap(), Err(Ended::Stopped));

        let fresh = Arc::new(super::tests::sequence());
        for n in 0..MAX_UNREAD {
            fresh.report(item(&n.to_string())).await.unwrap();
        }
        assert!(matches!(
            fresh.report(item("never read")).await,
            Err(Ended::Failed(_))
        ));
    }

    #[test]
    fn overlapping_heals_are_refused() {
        let heals = Heals::default();
        heals.launch("pics/2026", &Arc::new(sequence())).unwrap();
        for (path, code) in [
            ("pics/2026", "XMinioHealAlreadyRunning"),
            ("pics", "XMinioHealOverlappingPaths"),
            ("pics/2026/a", "XMinioHealOverlappingPaths"),
            ("", "XMinioHealOverlappingPaths"),
        ] {
            let err = heals.launch(path, &Arc::new(sequence())).unwrap_err();
            assert_eq!(err.code().as_str(), code, "{path}");
        }
        heals.launch("docs", &Arc::new(sequence())).unwrap();
    }
}
