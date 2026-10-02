//! What `mc admin info` and the console show of a server (`info`, `storageinfo`,
//! `datausageinfo`), in `madmin`'s types.
//!
//! A drive is one server with one pool of one set, as a single-drive `MinIO` is; its
//! drives are the disks it uses (its own, and those of folder buckets kept elsewhere).
//! The KMS and the LDAP directory are asked whether they answer, each for at most
//! [`CHECK`].

use std::{collections::BTreeMap, time::Duration};

use http::header;
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::Serialize;
use teifs_types::admin::ServerConfig;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{admin::json, drive::REGION, minio_iam::query, routes::Routes};

/// How long the KMS or the directory has to answer.
const CHECK: Duration = Duration::from_secs(10);
const ONLINE: &str = "online";
const OFFLINE: &str = "offline";
/// `madmin.BackendType`'s `FS`, as `storageinfo` numbers it.
const FS: u8 = 1;
/// The language the server is built with, where `MinIO` names its Go.
const RUNTIME_VERSION: &str = concat!("rust", env!("CARGO_PKG_RUST_VERSION"));

/// A count, or why it isn't known (`madmin.Buckets`, `Objects`, …).
#[derive(Serialize, Default)]
struct Count {
    count: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

/// `madmin.Usage`.
#[derive(Serialize, Default)]
struct Size {
    size: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

/// `madmin.KMS`, `madmin.LDAP`.
#[derive(Serialize)]
struct Service {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
}

/// `madmin.Services`.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct Services {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kms_status: Vec<Service>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ldap: Option<Service>,
}

/// `madmin.ErasureBackend`, of the `FS` kind.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Backend {
    #[serde(rename = "backendType")]
    kind: &'static str,
    online_disks: usize,
    offline_disks: usize,
    #[serde(rename = "standardSCParity")]
    standard_sc_parity: u8,
    #[serde(rename = "rrSCParity")]
    rr_sc_parity: u8,
    total_sets: [usize; 1],
    #[serde(rename = "totalDrivesPerSet")]
    drives_per_set: [usize; 1],
}

/// `madmin.Disk`.
#[derive(Serialize)]
pub(crate) struct Disk {
    pub(crate) endpoint: String,
    path: String,
    state: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    uuid: String,
    major: u32,
    minor: u32,
    #[serde(rename = "totalspace")]
    total_space: u64,
    #[serde(rename = "usedspace")]
    used_space: u64,
    #[serde(rename = "availspace")]
    available_space: u64,
    used_inodes: u64,
    local: bool,
    pool_index: usize,
    set_index: usize,
    #[serde(rename = "disk_index")]
    index: usize,
}

/// `madmin.Version`, `BackendVersion`, `APIVersion`: `MinIO`'s backend format, which a
/// drive doesn't have.
#[derive(Serialize, Default)]
struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

#[derive(Serialize, Default)]
struct BackendVersion {
    current: Version,
    max: Version,
    min: Version,
}

#[derive(Serialize, Default)]
struct ApiVersion {
    backend: BackendVersion,
}

/// `madmin.MemStats`: Go's allocator's numbers, which a Rust server has none of.
#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct MemStats {
    alloc: u64,
    total_alloc: u64,
    mallocs: u64,
    frees: u64,
    heap_alloc: u64,
}

/// `madmin.ServerProperties`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Server {
    state: &'static str,
    endpoint: String,
    scheme: &'static str,
    uptime: u64,
    version: &'static str,
    network: BTreeMap<String, &'static str>,
    #[serde(rename = "drives")]
    disks: Vec<Disk>,
    #[serde(rename = "mem_stats")]
    mem_stats: MemStats,
    edition: &'static str,
    #[serde(rename = "is_leader")]
    is_leader: bool,
    #[serde(rename = "ilm_expiry_in_progress")]
    ilm_expiry_in_progress: bool,
    #[serde(rename = "api_version")]
    api_version: ApiVersion,
    /// Go's zero time: it isn't restarting.
    #[serde(rename = "restarting_since")]
    restarting_since: &'static str,
    /// Go's `GOMAXPROCS`: the threads that run requests at once.
    #[serde(rename = "go_max_procs")]
    go_max_procs: usize,
    #[serde(rename = "num_cpu")]
    num_cpu: usize,
    #[serde(rename = "runtime_version")]
    runtime_version: &'static str,
}

/// `madmin.ErasureSetInfo`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetInfo {
    id: usize,
    raw_usage: u64,
    raw_capacity: u64,
    usage: u64,
    objects_count: u64,
    versions_count: u64,
    delete_markers_count: u64,
    heal_disks: usize,
}

/// `madmin.InfoMessage`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InfoMessage {
    mode: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    domain: Vec<String>,
    region: &'static str,
    #[serde(rename = "sqsARN", skip_serializing_if = "Vec::is_empty")]
    sqs_arn: Vec<String>,
    #[serde(rename = "deploymentID")]
    deployment_id: String,
    buckets: Count,
    objects: Count,
    versions: Count,
    #[serde(rename = "deletemarkers")]
    delete_markers: Count,
    usage: Size,
    services: Services,
    backend: Backend,
    servers: [Server; 1],
    pools: BTreeMap<usize, BTreeMap<usize, SetInfo>>,
}

/// `madmin.BackendInfo`, with Go's field names.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct BackendInfo {
    #[serde(rename = "Type")]
    kind: u8,
    gateway_online: bool,
    online_disks: BTreeMap<String, usize>,
    offline_disks: BTreeMap<String, usize>,
}

/// `madmin.StorageInfo`, with Go's field names.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct StorageInfo {
    disks: Vec<Disk>,
    backend: BackendInfo,
}

/// `madmin.BucketUsageInfo`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BucketUsage {
    size: u64,
    #[serde(rename = "objectsPendingReplicationTotalSize")]
    replication_pending_size: u64,
    #[serde(rename = "objectsFailedReplicationTotalSize")]
    replication_failed_size: u64,
    #[serde(rename = "objectsReplicatedTotalSize")]
    replicated_size: u64,
    #[serde(rename = "objectReplicaTotalSize")]
    replica_size: u64,
    #[serde(rename = "objectsPendingReplicationCount")]
    replication_pending_count: u64,
    #[serde(rename = "objectsFailedReplicationCount")]
    replication_failed_count: u64,
    versions_count: u64,
    objects_count: u64,
    delete_markers_count: u64,
}

/// `madmin.DataUsageInfo`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataUsageInfo {
    last_update: String,
    objects_count: u64,
    objects_total_size: u64,
    versions_count: u64,
    delete_markers_count: u64,
    #[serde(rename = "objectsPendingReplicationTotalSize")]
    replication_pending_size: u64,
    #[serde(rename = "objectsFailedReplicationTotalSize")]
    replication_failed_size: u64,
    #[serde(rename = "objectsReplicatedTotalSize")]
    replicated_size: u64,
    #[serde(rename = "objectsReplicaTotalSize")]
    replica_size: u64,
    #[serde(rename = "objectsPendingReplicationCount")]
    replication_pending_count: u64,
    #[serde(rename = "objectsFailedReplicationCount")]
    replication_failed_count: u64,
    buckets_count: u64,
    #[serde(rename = "bucketsUsageInfo")]
    buckets_usage: BTreeMap<String, BucketUsage>,
    #[serde(rename = "capacity")]
    total_capacity: u64,
    #[serde(rename = "freeCapacity")]
    total_free_capacity: u64,
    #[serde(rename = "usedCapacity")]
    total_used_capacity: u64,
}

/// The disks the drive uses, as `madmin` describes drives; none (logged) when they
/// can't be read.
pub(crate) async fn disks(routes: &Routes) -> Vec<Disk> {
    let disks = routes
        .store
        .disks()
        .await
        .inspect_err(|err| tracing::error!(error = %err, "can't read the drive's disks"))
        .unwrap_or_default();
    let drive = &routes.store.format().drive;
    disks
        .into_iter()
        .enumerate()
        .map(|(index, disk)| {
            let path = disk.path.display().to_string();
            Disk {
                endpoint: path.clone(),
                path,
                state: "ok",
                // The drive's own disk carries its id, as a MinIO drive carries its format's.
                uuid: if index == 0 {
                    drive.clone()
                } else {
                    String::new()
                },
                major: 0,
                minor: 0,
                total_space: disk.total,
                used_space: disk.total.saturating_sub(disk.available),
                available_space: disk.available,
                used_inodes: 0,
                local: true,
                pool_index: 0,
                set_index: 0,
                index,
            }
        })
        .collect()
}

/// Where the KMS answers: one entry per endpoint, all as one check of the KMS found.
async fn kms_status(routes: &Routes, config: Option<&ServerConfig>) -> Vec<Service> {
    let (Some(kms), Some(config)) = (routes.store.kms(), config) else {
        return Vec::new();
    };
    let (_, endpoints) = crate::minio_kms::kind(Some(config));
    let status = match tokio::time::timeout(CHECK, kms.keys()).await {
        Ok(Ok(_)) => ONLINE,
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the KMS didn't answer");
            OFFLINE
        }
        Err(_) => {
            tracing::warn!("the KMS didn't answer in time");
            OFFLINE
        }
    };
    endpoints
        .into_iter()
        .map(|endpoint| Service {
            status,
            endpoint: Some(endpoint),
        })
        .collect()
}

/// Whether the LDAP directory answers, when there is one.
async fn ldap_status(routes: &Routes) -> Option<Service> {
    let directory = routes.iam.ldap()?;
    let status = match tokio::time::timeout(CHECK, directory.check()).await {
        Ok(Ok(())) => ONLINE,
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the LDAP directory didn't answer");
            OFFLINE
        }
        Err(_) => {
            tracing::warn!("the LDAP directory didn't answer in time");
            OFFLINE
        }
    };
    Some(Service {
        status,
        endpoint: None,
    })
}

/// The host the caller reached, as `madmin` names a server: `host:port`.
pub(crate) fn endpoint(routes: &Routes, req: &S3Request<Body>) -> String {
    req.headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| routes.config.as_ref().map(|c| c.listen.clone()))
        .unwrap_or_default()
}

/// Which of `mc admin info`'s calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `GET info`.
    Server,
    /// `GET storageinfo`.
    Storage,
    /// `GET datausageinfo`.
    DataUsage,
    /// `GET healthinfo` (`mc support diag`).
    Health,
    /// The server's pools (`mc admin decommission`, `mc admin rebalance`).
    Pools(crate::minio_pools::Call),
}

impl Kind {
    /// The call's name, as the audit log and traces name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Server => "ServerInfo",
            Self::Storage => "StorageInfo",
            Self::DataUsage => "DataUsageInfo",
            Self::Health => "HealthInfo",
            Self::Pools(call) => call.name(),
        }
    }

    pub(crate) async fn call(
        self,
        routes: &Routes,
        req: &S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        match self {
            Self::Server => info(routes, req).await,
            Self::Storage => storage_info(routes).await,
            Self::DataUsage => data_usage_info(routes, req).await,
            Self::Health => crate::minio_health::health_info(routes, req).await,
            Self::Pools(call) => call.call(routes, req),
        }
    }
}

/// What the drive holds: buckets, objects, versions, delete markers and bytes, or why
/// that can't be read (`madmin`'s counts with an `error`).
async fn counts(routes: &Routes) -> (Count, Count, Count, Count, Size) {
    match routes.store.usage().await {
        Ok(all) => {
            let total = all
                .iter()
                .fold(teifs_store::Usage::default(), |total, b| total + b.usage);
            let count = |count| Count {
                count,
                error: String::new(),
            };
            (
                count(u64::try_from(all.len()).unwrap_or(u64::MAX)),
                count(total.objects),
                count(total.versions),
                count(total.delete_markers),
                Size {
                    size: total.bytes,
                    error: String::new(),
                },
            )
        }
        Err(err) => {
            tracing::error!(error = %err, "can't read what the drive holds");
            let message = "The drive's usage can't be read.";
            let error = || Count {
                count: 0,
                error: message.to_owned(),
            };
            (
                error(),
                error(),
                error(),
                error(),
                Size {
                    size: 0,
                    error: message.to_owned(),
                },
            )
        }
    }
}

/// `GET info`.
async fn info(routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    Ok(json(&info_message(routes, req).await))
}

impl InfoMessage {
    /// Names the server by `name` wherever it's named, as `MinIO`'s strict anonymizing does.
    pub(crate) fn anonymize(&mut self, name: &str) {
        for server in &mut self.servers {
            name.clone_into(&mut server.endpoint);
            server.network = BTreeMap::from([(name.to_owned(), ONLINE)]);
        }
    }
}

/// What `GET info` answers.
pub(crate) async fn info_message(routes: &Routes, req: &S3Request<Body>) -> InfoMessage {
    let config = routes.config.as_deref();
    let disks = disks(routes).await;
    let (buckets, objects, versions, delete_markers, usage) = counts(routes).await;
    let raw_capacity = disks.iter().map(|d| d.total_space).sum();
    let raw_usage = disks.iter().map(|d| d.used_space).sum();
    let set = SetInfo {
        id: 0,
        raw_usage,
        raw_capacity,
        usage: usage.size,
        objects_count: objects.count,
        versions_count: versions.count,
        delete_markers_count: delete_markers.count,
        heal_disks: 0,
    };
    let endpoint = endpoint(routes, req);
    let cpus = std::thread::available_parallelism().map_or(1, usize::from);
    let server = Server {
        state: ONLINE,
        network: BTreeMap::from([(endpoint.clone(), ONLINE)]),
        endpoint,
        scheme: if config.is_some_and(|c| c.tls.is_some()) {
            "https"
        } else {
            "http"
        },
        uptime: routes.started.elapsed().unwrap_or(Duration::ZERO).as_secs(),
        version: env!("CARGO_PKG_VERSION"),
        mem_stats: MemStats::default(),
        edition: "",
        is_leader: true,
        ilm_expiry_in_progress: false,
        api_version: ApiVersion::default(),
        restarting_since: "0001-01-01T00:00:00Z",
        go_max_procs: cpus,
        num_cpu: cpus,
        runtime_version: RUNTIME_VERSION,
        disks,
    };
    InfoMessage {
        mode: ONLINE,
        domain: config.map(|c| c.domains.clone()).unwrap_or_default(),
        region: REGION,
        sqs_arn: config
            .map(|c| c.notify_targets.iter().map(|t| t.arn.clone()).collect())
            .unwrap_or_default(),
        deployment_id: routes.store.format().drive.clone(),
        buckets,
        objects,
        versions,
        delete_markers,
        usage,
        services: Services {
            kms_status: kms_status(routes, config).await,
            ldap: ldap_status(routes).await,
        },
        backend: Backend {
            kind: "FS",
            online_disks: server.disks.len(),
            offline_disks: 0,
            standard_sc_parity: 0,
            rr_sc_parity: 0,
            total_sets: [1],
            drives_per_set: [server.disks.len()],
        },
        servers: [server],
        pools: BTreeMap::from([(0, BTreeMap::from([(0, set)]))]),
    }
}

/// `GET storageinfo`.
async fn storage_info(routes: &Routes) -> S3Result<S3Response<Body>> {
    let disks = disks(routes).await;
    let online = disks
        .iter()
        .map(|d| (d.endpoint.clone(), 1))
        .collect::<BTreeMap<_, _>>();
    Ok(json(&StorageInfo {
        disks,
        backend: BackendInfo {
            kind: FS,
            gateway_online: false,
            online_disks: online,
            offline_disks: BTreeMap::new(),
        },
    }))
}

/// `GET datausageinfo[?capacity=true]`: what each bucket holds, and with `capacity`,
/// the room on the drive's disks.
async fn data_usage_info(routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let buckets = routes.store.usage().await.map_err(|err| {
        tracing::error!(error = %err, "can't read what the drive holds");
        s3s::S3Error::internal_error(err)
    })?;
    let total = buckets
        .iter()
        .fold(teifs_store::Usage::default(), |total, b| total + b.usage);
    let mut answer = DataUsageInfo {
        last_update: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        objects_count: total.objects,
        objects_total_size: total.bytes,
        versions_count: total.versions,
        delete_markers_count: total.delete_markers,
        replication_pending_size: 0,
        replication_failed_size: 0,
        replicated_size: 0,
        replica_size: 0,
        replication_pending_count: 0,
        replication_failed_count: 0,
        buckets_count: u64::try_from(buckets.len()).unwrap_or(u64::MAX),
        buckets_usage: buckets
            .into_iter()
            .map(|b| {
                (
                    b.name,
                    BucketUsage {
                        size: b.usage.bytes,
                        replication_pending_size: 0,
                        replication_failed_size: 0,
                        replicated_size: 0,
                        replica_size: 0,
                        replication_pending_count: 0,
                        replication_failed_count: 0,
                        versions_count: b.usage.versions,
                        objects_count: b.usage.objects,
                        delete_markers_count: b.usage.delete_markers,
                    },
                )
            })
            .collect(),
        total_capacity: 0,
        total_free_capacity: 0,
        total_used_capacity: 0,
    };
    // MinIO computes these after it has written its answer, so they never reach the
    // client; here they do.
    if query(req)
        .iter()
        .any(|(n, v)| n == "capacity" && v == "true")
    {
        let disks = disks(routes).await;
        answer.total_capacity = disks.iter().map(|d| d.total_space).sum();
        answer.total_free_capacity = disks.iter().map(|d| d.available_space).sum();
        answer.total_used_capacity = answer
            .total_capacity
            .saturating_sub(answer.total_free_capacity);
    }
    Ok(json(&answer))
}
