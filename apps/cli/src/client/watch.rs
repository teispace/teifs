//! `teifs watch`: a bucket's events (or every bucket's), as they happen, until Ctrl-C
//! or the server stops (as `mc watch` shows `MinIO`'s). It needs
//! `s3:ListenBucketNotification`, or `s3:ListenNotification` for every bucket.

use clap::Args;
use teifs_client::{EventRecord, ListenFilter, event_key_decoded};

use super::{Error, alias::Aliases, target::Target};
use crate::{admin, ui, units::size};

#[derive(Args)]
pub struct WatchArgs {
    /// `ALIAS` for every bucket's events, or `ALIAS/BUCKET[/PREFIX]`.
    target: String,
    /// The events: `put`, `delete`, `get`, `ilm` (lifecycle expirations), `bucket`
    /// (buckets created and removed), or S3's names (`s3:ObjectCreated:Copy`),
    /// comma-separated.
    #[arg(long, value_delimiter = ',', default_value = "put,delete,get")]
    events: Vec<String>,
    /// Only keys ending with this.
    #[arg(long, default_value = "")]
    suffix: String,
}

/// The events a short name stands for, or `name` itself.
fn events_of(name: &str) -> Vec<String> {
    let events: &[&str] = match name {
        "put" => &["s3:ObjectCreated:*"],
        "delete" => &["s3:ObjectRemoved:*"],
        "get" => &["s3:ObjectAccessed:*"],
        "ilm" => &["s3:LifecycleExpiration:*"],
        "bucket" => &["s3:BucketCreated:*", "s3:BucketRemoved:*"],
        other => return vec![other.to_owned()],
    };
    events.iter().map(|&e| e.to_owned()).collect()
}

pub async fn run(aliases: &Aliases, args: WatchArgs) -> Result<(), Error> {
    let remote = Target::parse(&args.target, aliases)?.remote("watch")?;
    let filter = ListenFilter {
        events: args.events.iter().flat_map(|e| events_of(e)).collect(),
        prefix: remote.key.clone(),
        suffix: args.suffix,
    };
    let client = admin::client_for(&remote.alias)?;
    let mut listen = client
        .listen(remote.bucket.as_deref(), &filter)
        .await
        .map_err(|e| Error::admin("can't watch the events", &e))?;
    ui::note(format!(
        "Watching `{}`; Ctrl-C stops.",
        remote.display(&remote.key)
    ));
    loop {
        let record = tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            record = listen.next() => record,
        };
        let Some(record) = record.map_err(|e| Error::admin("the watch stopped", &e))? else {
            ui::note("The server ended the watch: it's stopping.");
            return Ok(());
        };
        ui::item(|| line(&record), || admin::record("event", &record));
    }
}

/// An event in a line: when, what, on what, how big.
fn line(record: &EventRecord) -> String {
    // `2026-09-30T12:00:00.123Z` → `12:00:00.123`.
    let time = record.event_time.get(11..23).unwrap_or(&record.event_time);
    let object = &record.s3.object;
    let mut on = record.s3.bucket.name.clone();
    if !object.key.is_empty() {
        on.push('/');
        on.push_str(&event_key_decoded(&object.key));
    }
    let mut line = format!("{} {} {on}", ui::dim(time), record.event_name);
    if let Some(bytes) = object.size {
        line.push(' ');
        line.push_str(&ui::dim(size(bytes)));
    }
    if let Some(version) = &object.version_id {
        line.push(' ');
        line.push_str(&ui::dim(format!("version {version}")));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_stand_for_groups() {
        assert_eq!(events_of("put"), ["s3:ObjectCreated:*"]);
        assert_eq!(
            events_of("bucket"),
            ["s3:BucketCreated:*", "s3:BucketRemoved:*"]
        );
        assert_eq!(
            events_of("s3:ObjectCreated:Copy"),
            ["s3:ObjectCreated:Copy"]
        );
    }
}
