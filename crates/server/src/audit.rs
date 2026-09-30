//! The audit log's writers: the S3 service's entries, one JSON line each, to a file,
//! standard output or a webhook, each behind a bounded queue of its own, so a slow disk
//! or receiver never slows a request (an entry that doesn't fit is counted as dropped in
//! the metrics). A file is created owner-only, appended to, and reopened on `SIGHUP`,
//! after logrotate has moved it. A webhook gets what's queued in batches, sent as JSON
//! lines, and each batch is retried with growing pauses until it's taken.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use teifs_notify::{Backoff, Webhook};
use teifs_s3::AuditSink;
use teifs_types::audit::AuditEntry;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt, BufWriter},
    sync::mpsc,
    task::JoinHandle,
};

use crate::signals::Hangups;

/// How many entries wait for a writer before new ones are dropped.
const QUEUE: usize = 16_384;
/// The most entries a webhook gets in one request.
const BATCH: usize = 100;
/// How many more times a batch is tried once the server is stopping.
const TRIES_WHEN_STOPPING: u32 = 3;

/// Where the audit log goes.
#[derive(Debug, Clone)]
pub enum AuditTarget {
    /// Standard output (the server's own messages go to standard error).
    Stdout,
    /// A file, appended to.
    File(PathBuf),
    /// A webhook.
    Webhook(Webhook),
}

impl fmt::Display for AuditTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => f.write_str("standard output"),
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Webhook(hook) => f.write_str(&hook.shown()),
        }
    }
}

/// A writer's end of the service's queue.
#[derive(Debug)]
struct AuditLog {
    queue: mpsc::Sender<AuditEntry>,
}

/// Every writer's queue: an entry goes to each.
#[derive(Debug)]
pub(crate) struct AuditLogs(Vec<AuditLog>);

impl AuditSink for AuditLogs {
    /// Taken only if every writer took it; a refusal is counted once.
    fn log(&self, entry: AuditEntry) -> bool {
        let Some((last, others)) = self.0.split_last() else {
            return true;
        };
        let mut taken = true;
        for log in others {
            taken &= log.queue.try_send(entry.clone()).is_ok();
        }
        taken & last.queue.try_send(entry).is_ok()
    }
}

type Output = Box<dyn AsyncWrite + Send + Unpin>;

/// A writer's task: it ends, having written what's queued, once the service is gone.
pub(crate) type Writer = JoinHandle<()>;

/// Opens every target and starts writing to it.
pub(crate) fn start(
    targets: &[AuditTarget],
) -> Result<(Arc<AuditLogs>, Vec<Writer>), (AuditTarget, std::io::Error)> {
    let mut logs = Vec::new();
    let mut writers = Vec::new();
    for target in targets {
        let (queue, entries) = mpsc::channel(QUEUE);
        let writer = match target {
            AuditTarget::Webhook(hook) => {
                let client = teifs_notify::client()
                    .map_err(|e| (target.clone(), std::io::Error::other(e)))?;
                tokio::spawn(deliver(client, hook.clone(), entries))
            }
            AuditTarget::Stdout | AuditTarget::File(_) => {
                let output = open(target).map_err(|e| (target.clone(), e))?;
                tokio::spawn(write(target.clone(), output, entries))
            }
        };
        logs.push(AuditLog { queue });
        writers.push(writer);
    }
    Ok((Arc::new(AuditLogs(logs)), writers))
}

fn open(target: &AuditTarget) -> std::io::Result<Output> {
    Ok(match target {
        AuditTarget::File(path) => Box::new(tokio::fs::File::from_std(open_file(path)?)),
        AuditTarget::Stdout | AuditTarget::Webhook(_) => Box::new(tokio::io::stdout()),
    })
}

/// Opens a log file to append to, creating it readable only by its owner.
fn open_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

async fn write(target: AuditTarget, output: Output, mut entries: mpsc::Receiver<AuditEntry>) {
    let mut output = BufWriter::new(output);
    let mut hangups = Hangups::new();
    let mut failing = false;
    loop {
        tokio::select! {
            entry = entries.recv() => {
                let Some(entry) = entry else { break };
                let mut result = line(&mut output, &entry).await;
                // Whatever else is waiting goes out with it, then all of it at once.
                while result.is_ok()
                    && let Ok(entry) = entries.try_recv()
                {
                    result = line(&mut output, &entry).await;
                }
                if result.is_ok() {
                    result = output.flush().await;
                }
                match result {
                    Ok(()) => failing = false,
                    Err(err) if !failing => {
                        failing = true;
                        tracing::error!(error = %err, to = %target, "can't write the audit log");
                    }
                    Err(_) => {}
                }
            }
            () = hangups.next() => {
                if let AuditTarget::File(path) = &target {
                    let _ = output.flush().await;
                    match open_file(path) {
                        Ok(file) => {
                            output = BufWriter::new(Box::new(tokio::fs::File::from_std(file)));
                            tracing::info!(to = %target, "reopened the audit log");
                        }
                        Err(err) => tracing::error!(
                            error = %err,
                            to = %target,
                            "can't reopen the audit log; still writing where it was"
                        ),
                    }
                }
            }
        }
    }
    let _ = output.flush().await;
}

async fn line(output: &mut BufWriter<Output>, entry: &AuditEntry) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    output.write_all(&bytes).await
}

/// Sends what's queued to a webhook, a batch at a time, each tried until it's taken (a
/// few more times only, once the server is stopping).
async fn deliver(client: reqwest::Client, hook: Webhook, mut entries: mpsc::Receiver<AuditEntry>) {
    let to = hook.shown();
    let mut batch = Vec::with_capacity(BATCH);
    while let Some(entry) = entries.recv().await {
        batch.push(entry);
        while batch.len() < BATCH
            && let Ok(entry) = entries.try_recv()
        {
            batch.push(entry);
        }
        let mut body = Vec::new();
        for entry in batch.drain(..) {
            if serde_json::to_writer(&mut body, &entry).is_ok() {
                body.push(b'\n');
            }
        }
        let mut backoff = Backoff::new();
        let mut failing = false;
        let mut tries_left = TRIES_WHEN_STOPPING;
        loop {
            match hook
                .post(&client, "application/x-ndjson", body.clone())
                .await
            {
                Ok(()) => {
                    if failing {
                        tracing::info!(to, "the audit webhook takes entries again");
                    }
                    break;
                }
                Err(err) => {
                    if !failing {
                        failing = true;
                        tracing::error!(error = %err, to, "the audit webhook didn't take entries; trying again");
                    }
                    if entries.is_closed() {
                        tries_left -= 1;
                        if tries_left == 0 {
                            tracing::error!(
                                to,
                                "stopping with audit entries the webhook didn't take"
                            );
                            return;
                        }
                    }
                    tokio::time::sleep(backoff.next_pause()).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zeroize::Zeroizing;

    #[test]
    fn a_webhook_is_shown_without_its_secrets() {
        let hook = Webhook::new(
            "https://user:pass@logs.example:8443/in?key=secret#frag",
            Some(Zeroizing::new("t0ken".to_owned())),
        )
        .unwrap();
        let shown = AuditTarget::Webhook(hook.clone()).to_string();
        assert_eq!(shown, "https://logs.example:8443/in");
        let debug = format!("{hook:?}");
        for secret in ["user", "pass", "secret", "frag", "t0ken"] {
            assert!(!debug.contains(secret), "{debug}");
        }
        for bad in [
            "ftp://logs.example",
            "file:///tmp/x",
            "not a url",
            "http://",
        ] {
            assert!(Webhook::new(bad, None).is_err(), "{bad}");
        }
    }
}
