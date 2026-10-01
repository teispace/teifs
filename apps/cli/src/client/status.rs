//! `teifs status ALIAS`: how a server is doing, as one list of checks: whether it answers
//! and how fast, whether its drive can serve and take writes, whether the two clocks
//! agree closely enough for signatures, when its certificate expires, and, with keys
//! that may read it, its version, disks, jobs and what its scrubs found. Exit code 1 when
//! a check fails.

use std::time::{Duration, SystemTime};

use teifs_client::{Client, HealthCheck};
use teifs_types::admin::ServerInfo;

use super::{Error, alias::Aliases};
use crate::{
    admin::client_for,
    checks::{self, Check, State},
    error::Kind,
};

/// How far apart the clocks may be before Signature V4 refuses requests.
const SIGNATURE_SKEW: Duration = Duration::from_mins(15);
/// How far apart the clocks may be before it's worth fixing.
const CLOCK_WARNING: Duration = Duration::from_mins(1);

/// `teifs status ALIAS`.
pub(crate) async fn status(alias: &str) -> Result<(), Error> {
    let aliases = Aliases::load()?;
    let (found, _) = aliases.get(alias).ok_or_else(|| {
        Error::new(Kind::NotFound, format!("there's no alias `{alias}`"))
            .with_hint("see `teifs alias ls`, or add one with `teifs alias set`")
    })?;
    found.check_usable(alias)?;
    let client = client_for(found)?;
    let checks = checks(&client, &found.url).await;
    checks::finish(&checks, ("server", &found.url))
}

/// Every check of the server at `url`, in order; those that need an answer stop at the
/// first that gets none.
async fn checks(client: &Client, url: &str) -> Vec<Check> {
    let mut checks = Vec::new();
    let live = match client.health(HealthCheck::Live).await {
        Ok(live) if live.status == 200 => live,
        Ok(live) => {
            checks.push(Check::new(
                "Server",
                State::Failed,
                format!(
                    "{url} answered {}, not 200: is it a TeiFS server?",
                    live.status
                ),
            ));
            return checks;
        }
        Err(err) => {
            checks.push(Check::new("Server", State::Failed, reason(url, &err)));
            return checks;
        }
    };
    checks.push(Check::new(
        "Server",
        State::Ok,
        format!("answers in {} ms", live.elapsed.as_millis()),
    ));
    if let Some(date) = live.date {
        checks.push(clock(date, SystemTime::now()));
    }
    for check in [HealthCheck::Ready, HealthCheck::Write] {
        checks.push(match client.health(check).await {
            Ok(answer) => drive(check, answer.status),
            Err(err) => Check::new(name_of(check), State::Failed, reason(url, &err)),
        });
    }
    if let Some(target) = url.strip_prefix("https://") {
        checks.push(certificate(target, SystemTime::now()).await);
    }
    match client.info().await {
        Ok(info) => checks.extend(server(&info)),
        Err(err) if err.code() == Some("AccessDenied") => checks.push(Check::new(
            "Server info",
            State::Warning,
            "these keys may not read it (teifs:GetServerInfo): version, disks, jobs and scrubs \
             aren't checked",
        )),
        Err(err) => checks.push(Check::new("Server info", State::Failed, reason(url, &err))),
    }
    checks
}

/// Why asking the server at `url` failed, with the hint for it.
fn reason(url: &str, err: &teifs_client::ClientError) -> String {
    let err = Error::admin(url, err);
    match err.hint {
        Some(hint) => format!("{}: {hint}", err.message),
        None => err.message,
    }
}

fn name_of(check: HealthCheck) -> &'static str {
    match check {
        HealthCheck::Live => "Server",
        HealthCheck::Ready => "Drive",
        HealthCheck::Write => "Writes",
    }
}

/// What a drive health check's status says.
fn drive(check: HealthCheck, status: u16) -> Check {
    let name = name_of(check);
    match (check, status) {
        (_, 200) if check == HealthCheck::Ready => Check::new(name, State::Ok, "serves"),
        (_, 200) => Check::new(name, State::Ok, "taken"),
        (HealthCheck::Ready, 503) => Check::new(
            name,
            State::Failed,
            "can't serve: its index is missing (a disk that went away?)",
        ),
        (_, 503) => Check::new(
            name,
            State::Failed,
            "refused: the disk is full (delete objects, or give it more room)",
        ),
        (_, status) => Check::new(
            name,
            State::Warning,
            format!("not checked: the server answered {status} (an older TeiFS?)"),
        ),
    }
}

/// How far the server's clock (`server`) is from this one (`here`).
fn clock(server: SystemTime, here: SystemTime) -> Check {
    let (apart, side) = match server.duration_since(here) {
        Ok(ahead) => (ahead, "ahead of"),
        Err(behind) => (behind.duration(), "behind"),
    };
    // A `Date` header is to the second.
    let seconds = apart.as_secs();
    let detail = format!("the server's is {seconds} s {side} this machine's");
    if apart >= SIGNATURE_SKEW {
        Check::new(
            "Clock",
            State::Failed,
            format!("{detail}: signed requests fail past 15 minutes; set both clocks from NTP"),
        )
    } else if apart >= CLOCK_WARNING {
        Check::new(
            "Clock",
            State::Warning,
            format!("{detail}: set both clocks from NTP"),
        )
    } else if seconds <= 1 {
        Check::new("Clock", State::Ok, "agrees with this machine's")
    } else {
        Check::new("Clock", State::Ok, detail)
    }
}

/// When the certificate the server at `target` presents expires, from `now`.
async fn certificate(target: &str, now: SystemTime) -> Check {
    let target = if target.contains(':') {
        target.to_owned()
    } else {
        format!("{target}:443")
    };
    match crate::health::certificate(&target).await {
        Ok(der) => Check::named("Certificate", checks::expiry(checks::not_after(&der), now)),
        Err(err) => Check::new(
            "Certificate",
            State::Failed,
            format!("can't read it: {err}"),
        ),
    }
}

/// What the server says about itself.
fn server(info: &ServerInfo) -> Vec<Check> {
    let mut checks = Vec::new();
    let here = env!("CARGO_PKG_VERSION");
    checks.push(if info.version == here {
        Check::new("Version", State::Ok, format!("TeiFS {here}"))
    } else {
        Check::new(
            "Version",
            State::Warning,
            format!(
                "the server runs TeiFS {}, this command is {here}",
                info.version
            ),
        )
    });
    for disk in &info.disks {
        let found = checks::disk(&disk.path, disk.total, disk.free, disk.reserved);
        checks.push(Check::named("Disk", found));
    }
    for (name, job) in &info.jobs {
        if let Some(error) = &job.last_error {
            checks.push(Check::new(
                "Job",
                State::Warning,
                format!("{name}: {error}"),
            ));
        }
    }
    let damaged: u64 = [&info.scrub.last, &info.scrub.current]
        .into_iter()
        .flatten()
        .map(|pass| pass.damaged)
        .sum();
    if damaged > 0 {
        checks.push(Check::new(
            "Scrub",
            State::Failed,
            format!("found {damaged} damaged versions: see `teifs admin info`"),
        ));
    } else if info.scrub.last.is_some() {
        checks.push(Check::new("Scrub", State::Ok, "found no damage"));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn clocks_apart_are_told_by_how_far() {
        let here = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(clock(here, here).state, State::Ok);
        assert_eq!(
            clock(here + Duration::from_secs(1), here).detail,
            "agrees with this machine's"
        );
        let close = clock(here - Duration::from_secs(30), here);
        assert_eq!(
            (close.state, close.detail.as_str()),
            (State::Ok, "the server's is 30 s behind this machine's")
        );
        assert_eq!(clock(here + MINUTE, here).state, State::Warning);
        assert_eq!(
            clock(here + 15 * MINUTE - Duration::from_secs(1), here).state,
            State::Warning
        );
        let far = clock(here + 15 * MINUTE, here);
        assert_eq!(far.state, State::Failed);
        assert!(
            far.detail.starts_with("the server's is 900 s ahead of"),
            "{}",
            far.detail
        );
        assert_eq!(clock(here - 15 * MINUTE, here).state, State::Failed);
    }

    #[test]
    fn drive_checks_are_read_from_their_status() {
        assert_eq!(drive(HealthCheck::Ready, 200).state, State::Ok);
        assert_eq!(drive(HealthCheck::Write, 200).detail, "taken");
        let gone = drive(HealthCheck::Ready, 503);
        assert_eq!((gone.name, gone.state), ("Drive", State::Failed));
        assert!(gone.detail.contains("index is missing"));
        let full = drive(HealthCheck::Write, 503);
        assert_eq!((full.name, full.state), ("Writes", State::Failed));
        assert!(full.detail.contains("disk is full"));
        assert_eq!(drive(HealthCheck::Write, 404).state, State::Warning);
    }

    #[test]
    fn what_a_server_says_is_checked() {
        use teifs_types::admin::{DiskInfo, JobInfo};
        let gib = 1 << 30;
        let mut info = ServerInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            drive: "d".into(),
            account: "123456789012".into(),
            started_ms: 0,
            uptime_seconds: 0,
            jobs: std::collections::BTreeMap::new(),
            scrub: teifs_types::verify::ScrubReport::default(),
            usage: None,
            disks: vec![
                DiskInfo {
                    path: "/ok".into(),
                    total: 100 * gib,
                    free: 50 * gib,
                    reserved: gib / 10,
                },
                DiskInfo {
                    path: "/low".into(),
                    total: 100 * gib,
                    free: 4 * gib,
                    reserved: gib / 10,
                },
                DiskInfo {
                    path: "/full".into(),
                    total: 100 * gib,
                    free: gib / 10,
                    reserved: gib / 10,
                },
            ],
        };
        let states = |info: &ServerInfo| -> Vec<(&'static str, State)> {
            server(info).iter().map(|c| (c.name, c.state)).collect()
        };
        assert_eq!(
            states(&info),
            [
                ("Version", State::Ok),
                ("Disk", State::Ok),
                ("Disk", State::Warning),
                ("Disk", State::Failed)
            ]
        );
        info.version = "0.0.1".into();
        info.disks.clear();
        info.jobs.insert(
            "lifecycle".into(),
            JobInfo {
                last_error: Some("can't read".into()),
                ..JobInfo::default()
            },
        );
        info.scrub.last = Some(teifs_types::verify::ScrubPass {
            damaged: 2,
            ..Default::default()
        });
        assert_eq!(
            states(&info),
            [
                ("Version", State::Warning),
                ("Job", State::Warning),
                ("Scrub", State::Failed)
            ]
        );
        info.scrub.last = Some(teifs_types::verify::ScrubPass::default());
        assert_eq!(server(&info).last().unwrap().state, State::Ok);
    }
}
