//! `teidrive`: serve a folder as a drive over S3, and manage it from the terminal.

mod credentials;

use std::{net::SocketAddr, path::PathBuf, process::ExitCode, time::SystemTime};

use clap::{Parser, Subcommand};
use teidrive_s3::Options;
use teidrive_store::{ListQuery, Store};

#[derive(Parser)]
#[command(
    name = "teidrive",
    version,
    about = "Your folders as a drive and as S3"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve a drive over the S3 API. Every folder in it is a bucket.
    Serve {
        /// The drive's folder (created if missing).
        #[arg(default_value = ".", env = "TEIDRIVE_DIR")]
        dir: PathBuf,
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:9000", env = "TEIDRIVE_LISTEN")]
        listen: SocketAddr,
        /// A domain for virtual-hosted-style requests (bucket.domain); repeatable.
        #[arg(long = "domain", env = "TEIDRIVE_DOMAINS", value_delimiter = ',')]
        domains: Vec<String>,
        /// The access key (else one is generated and kept in the drive).
        #[arg(long, env = "TEIDRIVE_ACCESS_KEY")]
        access_key: Option<String>,
        /// The secret key; only through the environment, so it never shows in a process list.
        #[arg(skip)]
        secret_key: Option<String>,
    },
    /// Show the drive's access key and where its secret is kept.
    Credentials {
        /// The drive's folder.
        #[arg(default_value = ".", env = "TEIDRIVE_DIR")]
        dir: PathBuf,
    },
    /// List, create or remove buckets.
    Bucket {
        #[command(subcommand)]
        action: BucketAction,
    },
    /// List a bucket's objects.
    Ls {
        /// The bucket.
        bucket: String,
        /// Only keys starting with this.
        #[arg(default_value = "")]
        prefix: String,
        /// List everything under the prefix, not just one level.
        #[arg(short, long)]
        recursive: bool,
        /// The drive's folder.
        #[arg(long, default_value = ".", env = "TEIDRIVE_DIR")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum BucketAction {
    /// List buckets.
    List {
        #[arg(long, default_value = ".", env = "TEIDRIVE_DIR")]
        dir: PathBuf,
    },
    /// Create a bucket.
    Create {
        name: String,
        #[arg(long, default_value = ".", env = "TEIDRIVE_DIR")]
        dir: PathBuf,
    },
    /// Remove an empty bucket.
    Remove {
        name: String,
        #[arg(long, default_value = ".", env = "TEIDRIVE_DIR")]
        dir: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("TEIDRIVE_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new().expect("a Tokio runtime");
    match runtime.block_on(run(cli.command)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("teidrive: {message}");
            ExitCode::FAILURE
        }
    }
}

fn open(dir: &PathBuf) -> Result<Store, String> {
    Store::open(dir).map_err(|e| format!("can't open the drive at {}: {e}", dir.display()))
}

async fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Serve {
            dir,
            listen,
            domains,
            access_key,
            ..
        } => serve(&dir, listen, domains, access_key).await,
        Command::Credentials { dir } => {
            let store = open(&dir)?;
            let (credentials, _) = credentials::load_or_create(store.root())
                .map_err(|e| format!("can't read the credentials: {e}"))?;
            println!("Access key: {}", credentials.access_key);
            println!(
                "Secret key: in {}",
                credentials::path(store.root()).display()
            );
            Ok(())
        }
        Command::Bucket { action } => bucket(action).await,
        Command::Ls {
            bucket,
            prefix,
            recursive,
            dir,
        } => ls(&open(&dir)?, &bucket, prefix, recursive).await,
    }
}

async fn serve(
    dir: &PathBuf,
    listen: SocketAddr,
    domains: Vec<String>,
    access_key: Option<String>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("can't create {}: {e}", dir.display()))?;
    let store = open(dir)?;
    let credentials = if let Some(access_key) = access_key {
        let secret_key = std::env::var("TEIDRIVE_SECRET_KEY")
            .map_err(|_| "set TEIDRIVE_SECRET_KEY along with the access key".to_owned())?;
        credentials::Credentials {
            access_key,
            secret_key,
        }
    } else {
        let (credentials, created) = credentials::load_or_create(store.root())
            .map_err(|e| format!("can't read the credentials: {e}"))?;
        if created {
            eprintln!(
                "Created credentials for this drive in {}",
                credentials::path(store.root()).display()
            );
        }
        credentials
    };
    let service = teidrive_s3::service(
        store.clone(),
        Options {
            credentials: Some((credentials.access_key.clone(), credentials.secret_key)),
            domains,
        },
    )
    .map_err(|e| format!("invalid domain: {e}"))?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("can't listen on {listen}: {e}"))?;
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!(
        "Serving {} over S3 at http://{address}",
        store.root().display()
    );
    eprintln!(
        "Access key: {}  (secret: `teidrive credentials`)",
        credentials.access_key
    );
    teidrive_s3::server::serve(listener, service, shutdown_signal()).await;
    eprintln!("Stopped.");
    Ok(())
}

async fn bucket(action: BucketAction) -> Result<(), String> {
    match action {
        BucketAction::List { dir } => {
            for bucket in open(&dir)?
                .list_buckets()
                .await
                .map_err(|e| e.to_string())?
            {
                println!("{}  {}", date(bucket.created), bucket.name);
            }
        }
        BucketAction::Create { name, dir } => {
            open(&dir)?
                .create_bucket(&name)
                .await
                .map_err(|e| format!("can't create {name}: {e}"))?;
            println!("Created {name}");
        }
        BucketAction::Remove { name, dir } => {
            open(&dir)?
                .delete_bucket(&name)
                .await
                .map_err(|e| format!("can't remove {name}: {e}"))?;
            println!("Removed {name}");
        }
    }
    Ok(())
}

/// Prints a bucket's objects and folders in key order, page by page.
async fn ls(store: &Store, bucket: &str, prefix: String, recursive: bool) -> Result<(), String> {
    let mut query = ListQuery {
        prefix,
        delimiter: (!recursive).then(|| "/".to_owned()),
        after: None,
        max_keys: 1000,
    };
    loop {
        let page = store
            .list(bucket, query.clone())
            .await
            .map_err(|e| format!("can't list {bucket}: {e}"))?;
        let mut lines: Vec<(&str, String)> = page
            .prefixes
            .iter()
            .map(|p| (p.as_str(), format!("{:>19}  {:>12}  {p}", "", "DIR")))
            .chain(page.objects.iter().map(|o| {
                (
                    o.key.as_str(),
                    format!("{}  {:>12}  {}", date(o.modified), o.size, o.key),
                )
            }))
            .collect();
        lines.sort_by(|a, b| a.0.cmp(b.0));
        for (_, line) in lines {
            println!("{line}");
        }
        if !page.truncated {
            return Ok(());
        }
        query.after = page.next;
    }
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
fn date(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("a SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("Stopping…");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(date(SystemTime::UNIX_EPOCH), "1970-01-01 00:00:00");
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_790_000_000);
        assert_eq!(date(t), "2026-09-21 14:13:20");
    }
}
