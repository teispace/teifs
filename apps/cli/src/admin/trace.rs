//! `teifs admin trace`: each request a server answers, as it answers it (as
//! `mc admin trace` shows `MinIO`'s), until Ctrl-C or the server stops.

use std::time::Duration;

use clap::Args;
use teifs_client::{AuditEntry, TraceFilter};

use super::{client, record};
use crate::{
    client::alias::Aliases,
    error::Error,
    ui,
    units::{parse_duration, size},
};

#[derive(Args)]
pub struct TraceArgs {
    /// The server's alias.
    alias: String,
    /// Only errors: answers from 400 up.
    #[arg(long, short)]
    errors: bool,
    /// Only this operation (`PutObject`, `GetObject`, `ListObjectsV2`…); repeat for more.
    #[arg(long = "api", value_name = "NAME")]
    apis: Vec<String>,
    /// Only requests on this bucket.
    #[arg(long)]
    bucket: Option<String>,
    /// Only requests on keys starting with this.
    #[arg(long)]
    prefix: Option<String>,
    /// Only this HTTP status (`404`); repeat for more.
    #[arg(long = "status", value_name = "CODE")]
    statuses: Vec<u16>,
    /// Only requests that took at least this long (`250ms`, `2s`).
    #[arg(long, value_name = "TIME", value_parser = parse_threshold)]
    slower_than: Option<Duration>,
}

/// `250ms`, or a duration [`parse_duration`] reads.
fn parse_threshold(text: &str) -> Result<Duration, String> {
    match text.trim().strip_suffix("ms") {
        Some(ms) => ms
            .parse()
            .map(Duration::from_millis)
            .map_err(|_| format!("`{text}` isn't a time like 250ms or 2s")),
        None => parse_duration(text),
    }
}

pub async fn run(aliases: &Aliases, args: TraceArgs) -> Result<(), Error> {
    let filter = TraceFilter {
        errors: args.errors,
        apis: args.apis,
        bucket: args.bucket,
        prefix: args.prefix,
        statuses: args.statuses,
        slower_than_ms: args
            .slower_than
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
    };
    let client = client(aliases, &args.alias)?;
    let mut trace = client
        .trace(&filter)
        .await
        .map_err(|e| Error::admin("can't trace the server's requests", &e))?;
    ui::note(format!(
        "Tracing requests to `{}`; Ctrl-C stops.",
        args.alias
    ));
    loop {
        let entry = tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            entry = trace.next() => entry,
        };
        let Some(entry) = entry.map_err(|e| Error::admin("the trace stopped", &e))? else {
            ui::note("The server ended the trace: it's stopping.");
            return Ok(());
        };
        ui::item(|| line(&entry), || record("trace", &entry));
    }
}

/// A request in a line: when, status, operation, what on, from where, how long, bytes.
fn line(entry: &AuditEntry) -> String {
    let api = &entry.api;
    // `2026-09-30T12:00:00.123456789Z` → `12:00:00.123`.
    let time = entry.time.get(11..23).unwrap_or(&entry.time);
    let on = match (api.bucket.as_str(), api.object.as_str()) {
        ("", _) => String::new(),
        (bucket, "") => bucket.to_owned(),
        (bucket, key) => format!("{bucket}/{key}"),
    };
    let took = api
        .time_to_response_in_ns
        .parse()
        .map(|ns: u64| took(Duration::from_nanos(ns)))
        .unwrap_or_default();
    let mut line = format!(
        "{} {} {} {} {} {} {}",
        ui::dim(time),
        api.status_code,
        api.name,
        on,
        ui::dim(&entry.remote_host),
        took,
        ui::dim(format!("↑{} ↓{}", size(api.rx), size(api.tx))),
    );
    if !entry.error.is_empty() {
        line.push(' ');
        line.push_str(&entry.error);
    }
    line
}

/// `350µs`, `12.4ms`, `2.1s`.
fn took(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros < 1000 {
        format!("{micros}µs")
    } else if micros < 1_000_000 {
        format!("{}.{}ms", micros / 1000, micros % 1000 / 100)
    } else {
        format!("{}.{}s", micros / 1_000_000, micros % 1_000_000 / 100_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_and_times_read_as_people_write_them() {
        assert_eq!(parse_threshold("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_threshold("2s"), Ok(Duration::from_secs(2)));
        assert!(parse_threshold("fast").is_err());
        assert!(parse_threshold("1.5ms").is_err());
        assert_eq!(took(Duration::from_micros(350)), "350µs");
        assert_eq!(took(Duration::from_micros(12_460)), "12.4ms");
        assert_eq!(took(Duration::from_millis(2_150)), "2.1s");
    }
}
