//! `MinIO`'s health report (`mc support diag`, and `mc admin obd` before it): `GET
//! healthinfo` (or `obdinfo`) streams `madmin.HealthInfo`, version 3, as it's gathered.
//!
//! Each part the query asks for (`syscpu`, `sysdrivehw`, `sysosinfo`, `sysmem`, `sysnet`,
//! `sysprocess`, `syserrors`, `sysservices`, `sysconfig`, `minioconfig`, `minioinfo`) is
//! added in turn, and the report so far is sent again after each, as `MinIO` sends it:
//! the client keeps the last. A space keeps a quiet answer alive, and gathering stops at
//! the `deadline` (a Go duration, ten seconds unless told). With `anonymize=strict` the
//! server is named `server1` wherever its address or host name would be.
//!
//! The host's figures are the machine's, as `MinIO` reports them; the process is the
//! server's own. The configuration is the drive's, with the secrets set reading
//! `*redacted*`.

use std::{collections::BTreeMap, fmt::Debug, path::Path, time::Duration};

use bytes::Bytes;
use http::{HeaderValue, header};
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sysinfo::{
    CpuRefreshKind, Disks, MemoryRefreshKind, Networks, Pid, ProcessRefreshKind, ProcessStatus,
    ProcessesToUpdate, RefreshKind, System, UpdateKind,
};
use teifs_types::config_kv;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::mpsc;

use crate::{
    lines,
    minio_iam::{invalid, query},
    minio_info,
    routes::Routes,
};

/// The report's version, `madmin.HealthInfoVersion3`.
const VERSION: &str = "3";
/// How long gathering may take unless the query says.
const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);
/// How often a quiet report sends a space, as `MinIO`'s does.
const KEEP_ALIVE: Duration = Duration::from_secs(5);
/// The pause after the first answer. madmin reads it with a decoder of its own and hands
/// the rest of the body to the client's, so what that decoder read ahead would be lost:
/// the rest arrives later. It's also what the process's CPU use is measured over (at
/// least `sysinfo`'s shortest interval).
const GAP: Duration = Duration::from_millis(250);
/// What the server is called when anonymized, as `MinIO` calls a single server.
const ANONYMOUS: &str = "server1";

/// The certificates a server presents, for the report's TLS part.
pub trait ServingCertificates: Send + Sync + Debug + 'static {
    /// The certificates in use now, each the server's own (DER), not its chain.
    fn leaves(&self) -> Vec<Vec<u8>>;
}

/// The parts a query asks for.
#[derive(Debug, Default, Clone, Copy)]
#[allow(clippy::struct_excessive_bools, reason = "the query's flags, one each")]
struct Asked {
    cpu: bool,
    drives: bool,
    os: bool,
    memory: bool,
    network: bool,
    process: bool,
    errors: bool,
    services: bool,
    config: bool,
    minio_config: bool,
    minio_info: bool,
}

impl Asked {
    fn parse(query: &[(String, String)]) -> Self {
        let on = |name: &str| query.iter().any(|(n, v)| n == name && v == "true");
        Self {
            cpu: on("syscpu"),
            drives: on("sysdrivehw"),
            os: on("sysosinfo"),
            memory: on("sysmem"),
            network: on("sysnet"),
            process: on("sysprocess"),
            errors: on("syserrors"),
            services: on("sysservices"),
            config: on("sysconfig"),
            minio_config: on("minioconfig"),
            minio_info: on("minioinfo"),
        }
    }
}

/// `madmin.HealthInfo`.
#[derive(Serialize)]
struct Report {
    version: &'static str,
    timestamp: String,
    sys: Sys,
    minio: Minio,
}

/// `madmin.SysInfo`.
#[derive(Serialize, Default)]
struct Sys {
    #[serde(rename = "cpus", skip_serializing_if = "Vec::is_empty")]
    cpus: Vec<Cpus>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    partitions: Vec<Partitions>,
    #[serde(rename = "osinfo", skip_serializing_if = "Vec::is_empty")]
    os_info: Vec<OsInfo>,
    #[serde(rename = "meminfo", skip_serializing_if = "Vec::is_empty")]
    mem_info: Vec<MemInfo>,
    #[serde(rename = "procinfo", skip_serializing_if = "Vec::is_empty")]
    proc_info: Vec<ProcInfo>,
    #[serde(rename = "netinfo", skip_serializing_if = "Vec::is_empty")]
    net_info: Vec<NetInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<SysErrors>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    services: Vec<SysServices>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    config: Vec<SysConfig>,
    /// Filled in only on Kubernetes, which the server doesn't ask.
    kubernetes: Map<String, Value>,
}

/// `madmin.MinioHealthInfo`.
#[derive(Serialize)]
struct Minio {
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<MinioConfig>,
    /// The deployment's id until `minioinfo` is gathered, then `madmin.MinioInfo`.
    info: Value,
}

/// `madmin.MinioConfig`: the configuration, by sub-system and target, or why not.
#[derive(Serialize)]
struct MinioConfig {
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<BTreeMap<&'static str, BTreeMap<String, Vec<Kv>>>>,
}

/// `MinIO`'s `config.KV`.
#[derive(Serialize)]
struct Kv {
    key: String,
    value: String,
}

/// `madmin.MinioInfo`: `GET info`'s answer and how the server is reached.
#[derive(Serialize)]
struct MinioInfo {
    #[serde(flatten)]
    info: minio_info::InfoMessage,
    tls: TlsInfo,
    is_kubernetes: bool,
    is_docker: bool,
}

/// `madmin.TLSInfo`.
#[derive(Serialize)]
struct TlsInfo {
    tls_enabled: bool,
    certs: Vec<TlsCert>,
}

/// `madmin.TLSCert`.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct TlsCert {
    pub_key_algo: String,
    signature_algo: String,
    not_before: String,
    not_after: String,
    checksum: String,
}

/// `madmin.CPUs`.
#[derive(Serialize)]
struct Cpus {
    addr: String,
    cpus: Vec<Cpu>,
}

/// `madmin.CPU`.
#[derive(Serialize)]
struct Cpu {
    vendor_id: String,
    family: String,
    model: String,
    stepping: i32,
    physical_id: String,
    model_name: String,
    mhz: f64,
    cache_size: i32,
    flags: Vec<String>,
    microcode: String,
    cores: usize,
}

/// `madmin.Partitions`.
#[derive(Serialize)]
struct Partitions {
    addr: String,
    partitions: Vec<Partition>,
}

/// `madmin.Partition`.
#[derive(Serialize)]
struct Partition {
    device: String,
    major: u32,
    minor: u32,
    mountpoint: String,
    fs_type: String,
    mount_options: &'static str,
    space_total: u64,
    space_free: u64,
}

/// `madmin.OSInfo`: gopsutil's `host.InfoStat`.
#[derive(Serialize)]
struct OsInfo {
    addr: String,
    info: HostInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostInfo {
    hostname: String,
    uptime: u64,
    boot_time: u64,
    procs: u64,
    os: &'static str,
    platform: String,
    platform_family: String,
    platform_version: String,
    kernel_version: String,
    kernel_arch: String,
    virtualization_system: &'static str,
    virtualization_role: &'static str,
    host_id: &'static str,
}

/// `madmin.MemInfo`.
#[derive(Serialize)]
struct MemInfo {
    addr: String,
    total: u64,
    used: u64,
    free: u64,
    available: u64,
    swap_space_total: u64,
    swap_space_free: u64,
    /// The control group's limit when it's lower, else the total.
    limit: u64,
}

/// `madmin.ProcInfo`, of the server's process.
#[derive(Serialize)]
struct ProcInfo {
    addr: String,
    pid: u32,
    cpu_percent: f64,
    cmd_line: String,
    /// Milliseconds since the epoch.
    create_time: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    cwd: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    exec_path: String,
    is_running: bool,
    mem_info: MemoryInfo,
    mem_percent: f32,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_fds: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_threads: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ppid: Option<u32>,
    status: String,
}

/// gopsutil's `process.MemoryInfoStat`.
#[derive(Serialize, Default)]
struct MemoryInfo {
    rss: u64,
    vms: u64,
}

/// `madmin.NetInfo`.
#[derive(Serialize)]
struct NetInfo {
    addr: String,
    interface: String,
}

/// `madmin.SysErrors`.
#[derive(Serialize)]
struct SysErrors {
    addr: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<&'static str>,
}

/// `madmin.SysServices`.
#[derive(Serialize)]
struct SysServices {
    addr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    services: Vec<SysService>,
}

/// `madmin.SysService`.
#[derive(Serialize)]
struct SysService {
    name: &'static str,
    status: String,
}

/// `madmin.SysConfig`.
#[derive(Serialize)]
struct SysConfig {
    addr: String,
    config: Map<String, Value>,
}

/// `GET /minio/admin/v3/healthinfo`.
pub(crate) async fn health_info(
    routes: &Routes,
    req: &S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let query = query(req);
    let deadline = match query.iter().find(|(n, _)| n == "deadline") {
        Some((_, text)) if !text.is_empty() => config_kv::go_duration(text)
            .map_err(|_| invalid(format!("The deadline {text:?} isn't a Go duration.")))?,
        _ => DEFAULT_DEADLINE,
    };
    let strict = query.iter().any(|(n, v)| n == "anonymize" && v == "strict");
    let endpoint = minio_info::endpoint(routes, req);
    let gathering = Gathering {
        asked: Asked::parse(&query),
        strict,
        addr: if strict {
            ANONYMOUS.to_owned()
        } else {
            endpoint.clone()
        },
        hosts: [
            endpoint,
            routes
                .config
                .as_ref()
                .map(|c| c.listen.clone())
                .unwrap_or_default(),
            System::host_name().unwrap_or_default(),
        ]
        .into_iter()
        .filter(|h| !h.is_empty())
        .collect(),
        info: minio_info::info_message(routes, req).await,
        config: minio_config(routes),
        tls: tls_info(routes),
    };
    let report = Report {
        version: VERSION,
        timestamp: rfc3339(OffsetDateTime::now_utc()),
        sys: Sys::default(),
        minio: Minio {
            config: None,
            info: json!({"deploymentID": routes.store.format().drive}),
        },
    };
    let (lines, body) = mpsc::channel(8);
    tokio::spawn(async move {
        let beat = async {
            let mut tick =
                tokio::time::interval_at(tokio::time::Instant::now() + KEEP_ALIVE, KEEP_ALIVE);
            loop {
                tick.tick().await;
                if lines.send(Bytes::from_static(b" ")).await.is_err() {
                    break;
                }
            }
        };
        tokio::select! {
            () = gathering.run(report, &lines) => {}
            () = beat => {}
            () = tokio::time::sleep(deadline) => {}
        }
    });
    let mut response = S3Response::new(lines::body(body));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
        .headers
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

/// What the report is made of, read from the server before it's streamed.
struct Gathering {
    asked: Asked,
    strict: bool,
    /// What the server is called: its address, or [`ANONYMOUS`].
    addr: String,
    /// The names that are the server's, replaced when anonymized.
    hosts: Vec<String>,
    info: minio_info::InfoMessage,
    config: MinioConfig,
    tls: TlsInfo,
}

impl Gathering {
    /// Sends the report, then again after each part it adds, until the client leaves.
    async fn run(self, mut report: Report, lines: &mpsc::Sender<Bytes>) {
        let send = |report: &Report| {
            let mut line = serde_json::to_vec(report).expect("a health report serializes");
            line.push(b'\n');
            lines.send(Bytes::from(line))
        };
        if send(&report).await.is_err() {
            return;
        }
        let Self {
            asked,
            strict,
            addr,
            hosts,
            mut info,
            config,
            tls,
        } = self;
        let host = {
            let addr = addr.clone();
            let hosts = hosts.clone();
            tokio::task::spawn_blocking(move || Host::read(asked, &addr, strict.then_some(&hosts)))
        };
        tokio::time::sleep(GAP).await;
        let Ok(mut host) = host.await else {
            return;
        };
        let parts: [(bool, AddPart); 9] = [
            (asked.cpu, |s, h| s.cpus.extend(h.cpus.take())),
            (asked.drives, |s, h| {
                s.partitions.extend(h.partitions.take());
            }),
            (asked.network, |s, h| s.net_info.extend(h.net.take())),
            (asked.os, |s, h| s.os_info.extend(h.os.take())),
            (asked.memory, |s, h| s.mem_info.extend(h.memory.take())),
            (asked.process, |s, h| s.proc_info.extend(h.process.take())),
            (asked.errors, |s, h| s.errors.extend(h.errors.take())),
            (asked.services, |s, h| s.services.extend(h.services.take())),
            (asked.config, |s, h| s.config.extend(h.config.take())),
        ];
        for (on, add) in parts {
            if on {
                add(&mut report.sys, &mut host);
                if send(&report).await.is_err() {
                    return;
                }
            }
        }
        if asked.minio_config {
            report.minio.config = Some(config);
            if send(&report).await.is_err() {
                return;
            }
        }
        if asked.minio_info {
            if strict {
                info.anonymize(ANONYMOUS);
            }
            let info = MinioInfo {
                info,
                tls,
                is_kubernetes: std::env::var_os("KUBERNETES_SERVICE_HOST")
                    .is_some_and(|h| !h.is_empty()),
                is_docker: ["/.dockerenv", "/run/.containerenv"]
                    .iter()
                    .any(|f| Path::new(f).exists()),
            };
            report.minio.info = serde_json::to_value(info).expect("server info serializes");
            let _ = send(&report).await;
        }
    }
}

/// Moves one part of what was read of the host into the report.
type AddPart = fn(&mut Sys, &mut Host);

/// The host's parts of the report, each read only when asked.
#[derive(Default)]
struct Host {
    cpus: Option<Cpus>,
    partitions: Option<Partitions>,
    net: Option<NetInfo>,
    os: Option<OsInfo>,
    memory: Option<MemInfo>,
    process: Option<ProcInfo>,
    errors: Option<SysErrors>,
    services: Option<SysServices>,
    config: Option<SysConfig>,
}

impl Host {
    /// Reads what `asked` asks for; `anonymize` names the server's names to replace.
    fn read(asked: Asked, addr: &str, anonymize: Option<&Vec<String>>) -> Self {
        let mut system = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );
        let me = sysinfo::get_current_pid().ok();
        let watched = || {
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always)
                .with_cwd(UpdateKind::Always)
                .with_tasks()
        };
        if let Some(me) = me.filter(|_| asked.process) {
            // CPU use is measured between two looks.
            system.refresh_processes_specifics(ProcessesToUpdate::Some(&[me]), true, watched());
            std::thread::sleep(GAP);
            system.refresh_processes_specifics(ProcessesToUpdate::Some(&[me]), true, watched());
        }
        if asked.os || asked.errors {
            system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                false,
                ProcessRefreshKind::nothing(),
            );
        }
        let addr = || addr.to_owned();
        let mut host = Self::default();
        if asked.cpu {
            host.cpus = Some(Cpus {
                addr: addr(),
                cpus: cpus(&system),
            });
        }
        if asked.drives {
            host.partitions = Some(Partitions {
                addr: addr(),
                partitions: partitions(),
            });
        }
        if asked.network {
            host.net = Some(net_info(addr()));
        }
        if asked.os {
            host.os = Some(os_info(&system, addr(), anonymize.is_some()));
        }
        if asked.memory {
            host.memory = Some(mem_info(&system, addr()));
        }
        if asked.process
            && let Some(process) = me.and_then(|me| proc_info(&system, me, addr(), anonymize))
        {
            host.process = Some(process);
        }
        if asked.errors {
            host.errors = Some(SysErrors {
                addr: addr(),
                errors: sys_errors(&system),
            });
        }
        if asked.services {
            host.services = Some(sys_services(addr()));
        }
        if asked.config {
            host.config = Some(SysConfig {
                addr: addr(),
                config: sys_config(),
            });
        }
        host
    }
}

/// The CPUs, as one kind: `MinIO`'s groups them by socket, which isn't known here.
fn cpus(system: &System) -> Vec<Cpu> {
    let Some(first) = system.cpus().first() else {
        return Vec::new();
    };
    vec![Cpu {
        vendor_id: first.vendor_id().to_owned(),
        family: String::new(),
        model: String::new(),
        stepping: 0,
        physical_id: "0".to_owned(),
        model_name: first.brand().trim().to_owned(),
        mhz: f64::from(u32::try_from(first.frequency()).unwrap_or(u32::MAX)),
        cache_size: 0,
        flags: Vec::new(),
        microcode: String::new(),
        cores: System::physical_core_count().unwrap_or(system.cpus().len()),
    }]
}

/// The mounted disks.
fn partitions() -> Vec<Partition> {
    let disks = Disks::new_with_refreshed_list();
    let mut partitions: Vec<Partition> = disks
        .list()
        .iter()
        .map(|disk| Partition {
            device: disk.name().to_string_lossy().into_owned(),
            major: 0,
            minor: 0,
            mountpoint: disk.mount_point().display().to_string(),
            fs_type: disk.file_system().to_string_lossy().into_owned(),
            mount_options: if disk.is_read_only() { "ro" } else { "rw" },
            space_total: disk.total_space(),
            space_free: disk.available_space(),
        })
        .collect();
    partitions.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
    partitions
}

/// The network interfaces with an address: `MinIO` reports the one its nodes talk on,
/// and a single server has none.
fn net_info(addr: String) -> NetInfo {
    let networks = Networks::new_with_refreshed_list();
    let mut names: Vec<&String> = networks
        .list()
        .iter()
        .filter(|(_, data)| !data.ip_networks().is_empty())
        .map(|(name, _)| name)
        .collect();
    names.sort();
    NetInfo {
        addr,
        interface: names
            .into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn os_info(system: &System, addr: String, anonymize: bool) -> OsInfo {
    OsInfo {
        addr,
        info: HostInfo {
            hostname: if anonymize {
                ANONYMOUS.to_owned()
            } else {
                System::host_name().unwrap_or_default()
            },
            uptime: System::uptime(),
            boot_time: System::boot_time(),
            procs: u64::try_from(system.processes().len()).unwrap_or(u64::MAX),
            os: std::env::consts::OS,
            platform: System::distribution_id(),
            platform_family: System::distribution_id_like()
                .into_iter()
                .next()
                .unwrap_or_default(),
            platform_version: System::os_version().unwrap_or_default(),
            kernel_version: System::kernel_version().unwrap_or_default(),
            kernel_arch: System::cpu_arch(),
            virtualization_system: "",
            virtualization_role: "",
            host_id: "",
        },
    }
}

fn mem_info(system: &System, addr: String) -> MemInfo {
    let total = system.total_memory();
    MemInfo {
        addr,
        total,
        used: system.used_memory(),
        free: system.free_memory(),
        available: system.available_memory(),
        swap_space_total: system.total_swap(),
        swap_space_free: system.free_swap(),
        limit: system
            .cgroup_limits()
            .map_or(total, |limits| limits.total_memory.min(total)),
    }
}

/// The server's process, its command line anonymized when asked.
fn proc_info(
    system: &System,
    me: Pid,
    addr: String,
    anonymize: Option<&Vec<String>>,
) -> Option<ProcInfo> {
    let process = system.process(me)?;
    let mut cmd_line = process
        .cmd()
        .iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    for host in anonymize.into_iter().flatten() {
        cmd_line = cmd_line.replace(host.as_str(), ANONYMOUS);
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "a percentage needs no more than f32's precision"
    )]
    let mem_percent = if system.total_memory() == 0 {
        0.0
    } else {
        (process.memory() as f64 / system.total_memory() as f64 * 100.0) as f32
    };
    Some(ProcInfo {
        addr,
        pid: me.as_u32(),
        cpu_percent: f64::from(process.cpu_usage()),
        cmd_line,
        create_time: process.start_time().saturating_mul(1000),
        cwd: process
            .cwd()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        exec_path: process
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        is_running: true,
        mem_info: MemoryInfo {
            rss: process.memory(),
            vms: process.virtual_memory(),
        },
        mem_percent,
        name: process.name().to_string_lossy().into_owned(),
        num_fds: process.open_files(),
        num_threads: process.tasks().map(|t| t.len().max(1)),
        ppid: process.parent().map(Pid::as_u32),
        status: status(process.status()),
    })
}

/// A process's state as gopsutil names it.
fn status(status: ProcessStatus) -> String {
    match status {
        ProcessStatus::Run => "running".to_owned(),
        ProcessStatus::Sleep => "sleep".to_owned(),
        ProcessStatus::Stop => "stop".to_owned(),
        ProcessStatus::Idle => "idle".to_owned(),
        ProcessStatus::Zombie => "zombie".to_owned(),
        ProcessStatus::UninterruptibleDiskSleep => "wait".to_owned(),
        ProcessStatus::LockBlocked => "lock".to_owned(),
        other => other.to_string().to_lowercase(),
    }
}

/// What `MinIO` warns of on Linux: the kernel's audit on (it slows every write), and
/// `updatedb` installed (it walks the drives).
fn sys_errors(system: &System) -> Vec<&'static str> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let mut errors = Vec::new();
    let audit = std::fs::read_to_string("/proc/cmdline").is_ok_and(|c| c.contains("audit=1"))
        || system.processes().values().any(|p| p.name() == "kauditd");
    if audit {
        errors.push("audit is enabled");
    }
    let updatedb = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("updatedb").is_file()));
    if updatedb {
        errors.push("updatedb is installed");
    }
    errors
}

/// `SELinux`'s mode, as `/etc/selinux/config` sets it.
fn sys_services(addr: String) -> SysServices {
    let (status, error) = match std::fs::read_to_string("/etc/selinux/config") {
        Ok(text) => (
            text.lines()
                .filter_map(|l| l.trim().split_once('='))
                .find(|(key, _)| *key == "SELINUX")
                .map(|(_, mode)| mode.to_owned())
                .unwrap_or_default(),
            String::new(),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            ("not-installed".to_owned(), String::new())
        }
        Err(err) => (String::new(), err.to_string()),
    };
    SysServices {
        addr,
        error,
        services: vec![SysService {
            name: "selinux",
            status,
        }],
    }
}

/// The host's settings `MinIO` checks: the open files limit, the clock, and on Linux
/// transparent huge pages, XFS's retries and the kernel's command line.
fn sys_config() -> Map<String, Value> {
    let mut config = Map::new();
    if let Some(limit) = System::open_files_limit() {
        config.insert("rlimit-max".to_owned(), json!(limit));
    }
    config.insert(
        "time-info".to_owned(),
        json!({
            "current_time": rfc3339(OffsetDateTime::now_utc()),
            "roundtrip_duration": 0,
            "time_zone": "UTC",
        }),
    );
    if cfg!(target_os = "linux") {
        let thp = Path::new("/sys/kernel/mm/transparent_hugepage");
        let mut pages = Map::new();
        for (name, file) in [
            ("enabled", "enabled"),
            ("defrag", "defrag"),
            ("max_ptes_none", "khugepaged/max_ptes_none"),
        ] {
            if let Ok(value) = std::fs::read_to_string(thp.join(file)) {
                pages.insert(name.to_owned(), json!(value.trim()));
            }
        }
        config.insert("thp-config".to_owned(), Value::Object(pages));
        let retries = xfs_retries(Path::new("/sys/fs/xfs"));
        if !retries.is_empty() {
            config.insert("xfs-error-config".to_owned(), json!({"configs": retries}));
        }
        if let Ok(line) = std::fs::read_to_string("/proc/cmdline") {
            let words: Vec<&str> = line.split_whitespace().collect();
            config.insert("proc-cmdline".to_owned(), json!(words));
        }
    }
    config
}

/// Each XFS file system's metadata error retries (`<fs>/error/metadata/<error>/
/// max_retries`), as `MinIO` lists them.
fn xfs_retries(root: &Path) -> Vec<Value> {
    let entries = |dir: &Path| -> Vec<std::path::PathBuf> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        paths
    };
    let mut retries = Vec::new();
    for fs in entries(root) {
        for error in entries(&fs.join("error/metadata")) {
            let file = error.join("max_retries");
            if let Some(max) = std::fs::read_to_string(&file)
                .ok()
                .and_then(|t| t.trim().parse::<i64>().ok())
            {
                retries
                    .push(json!({"config_file": file.display().to_string(), "max_retries": max}));
            }
        }
    }
    retries
}

/// The drive's configuration with its secrets redacted, or why it can't be read.
fn minio_config(routes: &Routes) -> MinioConfig {
    let loaded = crate::minio_config::configs(routes)
        .map_err(|_| "The server's settings aren't kept on its drive.".to_owned())
        .and_then(|configs| {
            configs.settings.files.load().map_err(|err| {
                tracing::error!(error = %err, "can't read the drive's configuration");
                "The drive's configuration can't be read.".to_owned()
            })
        });
    match loaded {
        Ok(config) => MinioConfig {
            error: String::new(),
            config: Some(
                config
                    .redacted()
                    .into_iter()
                    .map(|(subsystem, targets)| {
                        let targets = targets
                            .into_iter()
                            .map(|(target, kvs)| {
                                let kvs = kvs
                                    .into_iter()
                                    .map(|(key, value)| Kv { key, value })
                                    .collect();
                                (target, kvs)
                            })
                            .collect();
                        (subsystem, targets)
                    })
                    .collect(),
            ),
        },
        Err(error) => MinioConfig {
            error,
            config: None,
        },
    }
}

/// Whether the server serves TLS, and the certificates it presents.
fn tls_info(routes: &Routes) -> TlsInfo {
    let enabled = routes.config.as_ref().is_some_and(|c| c.tls.is_some());
    TlsInfo {
        tls_enabled: enabled,
        certs: routes
            .certificates
            .as_ref()
            .filter(|_| enabled)
            .map(|c| c.leaves())
            .unwrap_or_default()
            .iter()
            .filter_map(|der| tls_cert(der))
            .collect(),
    }
}

/// A certificate as `MinIO` describes it: Go's names for its algorithms, and its
/// checksum, the XOR of the xxh3 hashes of its issuer, public key and alternative names.
fn tls_cert(der: &[u8]) -> Option<TlsCert> {
    use x509_parser::extensions::GeneralName;

    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let tbs = &cert.tbs_certificate;
    let hash = xxhash_rust::xxh3::xxh3_64;
    let mut check = hash(tbs.issuer.as_raw()) ^ hash(tbs.subject_pki.raw);
    if let Ok(Some(names)) = tbs.subject_alternative_name() {
        for name in &names.value.general_names {
            check ^= match name {
                GeneralName::DNSName(n) | GeneralName::RFC822Name(n) | GeneralName::URI(n) => {
                    hash(n.as_bytes())
                }
                GeneralName::IPAddress(ip) => hash(ip_text(ip).as_bytes()),
                _ => 0,
            };
        }
    }
    let oid = |o: &x509_parser::der_parser::oid::Oid<'_>| o.to_id_string();
    let validity = tbs.validity();
    Some(TlsCert {
        pub_key_algo: public_key_algorithm(&oid(&tbs.subject_pki.algorithm.algorithm)),
        signature_algo: signature_algorithm(&oid(&cert.signature_algorithm.algorithm)),
        not_before: rfc3339(validity.not_before.to_datetime()),
        not_after: rfc3339(validity.not_after.to_datetime()),
        checksum: format!("{check:x}"),
    })
}

/// An address as Go writes a `net.IP`.
fn ip_text(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).map_or_else(
            |_| String::new(),
            |b| std::net::Ipv4Addr::from(b).to_string(),
        ),
        16 => <[u8; 16]>::try_from(bytes).map_or_else(
            |_| String::new(),
            |b| {
                let ip = std::net::Ipv6Addr::from(b);
                ip.to_ipv4_mapped()
                    .map_or_else(|| ip.to_string(), |v4| v4.to_string())
            },
        ),
        _ => String::new(),
    }
}

/// Go's `x509.PublicKeyAlgorithm` names.
fn public_key_algorithm(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10040.4.1" => "DSA",
        "1.2.840.10045.2.1" => "ECDSA",
        "1.3.101.112" => "Ed25519",
        other => other,
    }
    .to_owned()
}

/// Go's `x509.SignatureAlgorithm` names.
fn signature_algorithm(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "SHA1-RSA",
        "1.2.840.113549.1.1.11" => "SHA256-RSA",
        "1.2.840.113549.1.1.12" => "SHA384-RSA",
        "1.2.840.113549.1.1.13" => "SHA512-RSA",
        "1.2.840.10045.4.1" => "ECDSA-SHA1",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
        "1.3.101.112" => "Ed25519",
        other => other,
    }
    .to_owned()
}

/// A time as Go's JSON writes it.
fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn the_query_says_which_parts_to_gather() {
        let query: Vec<(String, String)> = [("syscpu", "true"), ("sysmem", "false")]
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        let asked = Asked::parse(&query);
        assert!(asked.cpu);
        assert!(!asked.memory && !asked.minio_info);
    }

    #[test]
    fn a_certificate_is_described_with_go_s_names() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["a.test".to_owned()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let described = tls_cert(cert.der()).unwrap();
        assert_eq!(described.pub_key_algo, "ECDSA");
        assert_eq!(described.signature_algo, "ECDSA-SHA256");
        assert!(
            described.not_before.ends_with('Z'),
            "{}",
            described.not_before
        );
        assert!(u64::from_str_radix(&described.checksum, 16).is_ok());
        assert_eq!(tls_cert(b"not a certificate"), None);
    }

    #[test]
    fn addresses_are_written_as_go_writes_them() {
        assert_eq!(ip_text(&[127, 0, 0, 1]), "127.0.0.1");
        let mapped = std::net::Ipv4Addr::new(10, 0, 0, 1)
            .to_ipv6_mapped()
            .octets();
        assert_eq!(ip_text(&mapped), "10.0.0.1");
        assert_eq!(ip_text(&std::net::Ipv6Addr::LOCALHOST.octets()), "::1");
    }

    #[test]
    fn xfs_retries_are_read_from_each_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let errors = dir.path().join("sda1/error/metadata/EIO");
        std::fs::create_dir_all(&errors).unwrap();
        std::fs::write(errors.join("max_retries"), "-1\n").unwrap();
        let retries = xfs_retries(dir.path());
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0]["max_retries"], -1);
        assert!(xfs_retries(&dir.path().join("missing")).is_empty());
    }

    #[test]
    fn the_host_is_read_for_what_is_asked() {
        let asked = Asked::parse(
            &[
                "syscpu",
                "sysdrivehw",
                "sysosinfo",
                "sysmem",
                "sysprocess",
                "sysservices",
                "sysconfig",
            ]
            .map(|n| (n.to_owned(), "true".to_owned())),
        );
        let hosts = vec!["example.test:9000".to_owned()];
        let host = Host::read(asked, ANONYMOUS, Some(&hosts));
        assert!(host.cpus.unwrap().cpus[0].cores > 0);
        assert!(host.memory.unwrap().total > 0);
        assert_eq!(host.os.unwrap().info.hostname, ANONYMOUS);
        let process = host.process.unwrap();
        assert_eq!(process.pid, std::process::id());
        assert!(process.mem_info.rss > 0);
        assert!(host.config.unwrap().config.contains_key("time-info"));
        assert!(host.net.is_none() && host.errors.is_none());
    }
}
