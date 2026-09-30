//! The audit log's writer: the S3 service's entries, one JSON line each, to a file or
//! standard output. A bounded queue stands between them, so a slow disk never slows a
//! request (an entry that doesn't fit is counted as dropped in the metrics). The file is
//! created owner-only, appended to, and reopened on `SIGHUP`, after logrotate has moved
//! it.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use teifs_s3::AuditSink;
use teifs_types::audit::AuditEntry;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt, BufWriter},
    sync::mpsc,
    task::JoinHandle,
};

use crate::signals::Hangups;

/// How many entries wait for the writer before new ones are dropped.
const QUEUE: usize = 16_384;

/// Where the audit log goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditTarget {
    /// Standard output (the server's own messages go to standard error).
    Stdout,
    /// A file, appended to.
    File(PathBuf),
}

impl fmt::Display for AuditTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => f.write_str("standard output"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// The service's end of the queue.
#[derive(Debug)]
pub(crate) struct AuditLog {
    queue: mpsc::Sender<AuditEntry>,
}

impl AuditSink for AuditLog {
    fn log(&self, entry: AuditEntry) -> bool {
        self.queue.try_send(entry).is_ok()
    }
}

type Output = Box<dyn AsyncWrite + Send + Unpin>;

/// The writer's task: it ends, having written everything queued, once every
/// [`AuditLog`] is dropped.
pub(crate) type Writer = JoinHandle<()>;

/// Opens `target` and starts writing to it.
pub(crate) fn start(target: &AuditTarget) -> std::io::Result<(Arc<AuditLog>, Writer)> {
    let output = open(target)?;
    let (queue, entries) = mpsc::channel(QUEUE);
    let writer = tokio::spawn(write(target.clone(), output, entries));
    Ok((Arc::new(AuditLog { queue }), writer))
}

fn open(target: &AuditTarget) -> std::io::Result<Output> {
    Ok(match target {
        AuditTarget::Stdout => Box::new(tokio::io::stdout()),
        AuditTarget::File(path) => Box::new(tokio::fs::File::from_std(open_file(path)?)),
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
