//! `teifs admin`: a TeiFS server's admin API through an alias — what the server is and
//! how it was started, moving its IAM, replacing its root key, and users with their keys
//! and policies (over AWS's IAM API, which `aws iam --endpoint-url …` speaks too).

mod users;

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Subcommand;
use serde_json::{Value, json};
use teifs_client::{Client, IamExport, Zeroizing};

use crate::{
    client::alias::{Alias, Aliases, Origin},
    error::{Error, Kind},
    ui,
    units::{from_ms, rfc3339},
};

#[derive(Subcommand)]
pub enum AdminAction {
    /// Show what a TeiFS server is and how it's doing: its version, drive, account,
    /// uptime and background jobs.
    Info {
        /// The server's alias.
        alias: String,
    },
    /// Show how a TeiFS server was started (never its secrets).
    Config {
        /// The server's alias.
        alias: String,
    },
    /// Export or import the account's IAM: users, groups, policies and access keys.
    Iam {
        #[command(subcommand)]
        action: IamAction,
    },
    /// Replace the root key a TeiFS server's drive generated.
    RootKey {
        #[command(subcommand)]
        action: RootKeyAction,
    },
    /// Add, list and delete users, their access keys and policies.
    User {
        #[command(subcommand)]
        action: users::UserAction,
    },
}

#[derive(Subcommand)]
pub enum IamAction {
    /// Write the account's IAM as JSON, to standard output or a file.
    Export {
        /// The server's alias.
        alias: String,
        /// The file to write (owner-only); standard output without it.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Include the access keys' secrets, so they keep working after an import (root
        /// user only; needs `--output`).
        #[arg(long)]
        secrets: bool,
        /// Replace the file if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Make an export in a server whose IAM is empty, all or nothing.
    Import {
        /// The server's alias.
        alias: String,
        /// The export: a file, or `-` for standard input.
        file: PathBuf,
        /// Take the export's account id too, so ARNs in policies and elsewhere keep
        /// naming the same account.
        #[arg(long)]
        adopt_account: bool,
    },
}

#[derive(Subcommand)]
pub enum RootKeyAction {
    /// Replace it: the old key stops working at once, the server's drive keeps the new
    /// one, and the alias is updated to use it.
    Rotate {
        /// The server's alias, signing with the root key.
        alias: String,
    },
}

pub async fn run(action: AdminAction) -> Result<(), Error> {
    let aliases = Aliases::load()?;
    match action {
        AdminAction::Info { alias } => info(&client(&aliases, &alias)?).await,
        AdminAction::Config { alias } => config(&client(&aliases, &alias)?).await,
        AdminAction::Iam {
            action:
                IamAction::Export {
                    alias,
                    output,
                    secrets,
                    force,
                },
        } => {
            export(
                &client(&aliases, &alias)?,
                output.as_deref(),
                secrets,
                force,
            )
            .await
        }
        AdminAction::Iam {
            action:
                IamAction::Import {
                    alias,
                    file,
                    adopt_account,
                },
        } => import(&client(&aliases, &alias)?, &file, adopt_account).await,
        AdminAction::RootKey {
            action: RootKeyAction::Rotate { alias },
        } => rotate(aliases, &alias).await,
        AdminAction::User { action } => users::run(aliases, action).await,
    }
}

fn alias<'a>(aliases: &'a Aliases, name: &str) -> Result<(&'a Alias, Origin), Error> {
    let found = aliases.get(name).ok_or_else(|| {
        Error::new(Kind::NotFound, format!("there's no alias `{name}`"))
            .with_hint("see `teifs alias ls`, or add one with `teifs alias set`")
    })?;
    found.0.check_fresh(name)?;
    Ok(found)
}

fn client_for(alias: &Alias) -> Result<Client, Error> {
    Client::new(
        &alias.url,
        &alias.access_key,
        Zeroizing::new(alias.secret_key.clone()),
    )
    .map(|client| {
        let client = client.with_region(&alias.region);
        match &alias.session_token {
            Some(token) => client.with_session_token(Zeroizing::new(token.clone())),
            None => client,
        }
    })
    .map_err(|e| Error::admin("can't use the alias", &e))
}

fn client(aliases: &Aliases, name: &str) -> Result<Client, Error> {
    client_for(alias(aliases, name)?.0)
}

/// A record for `--json`: `value`'s fields with a `type`.
fn record(kind: &str, value: &impl serde::Serialize) -> Value {
    let mut record = serde_json::to_value(value).unwrap_or(Value::Null);
    if let Value::Object(fields) = &mut record {
        fields.insert("type".into(), kind.into());
    }
    record
}

/// `90061s` as `1d 1h 1m`: the two largest units that aren't zero.
fn uptime(duration: Duration) -> String {
    let secs = duration.as_secs();
    let parts = [
        (secs / 86_400, "d"),
        (secs / 3_600 % 24, "h"),
        (secs / 60 % 60, "m"),
        (secs % 60, "s"),
    ];
    let shown: Vec<String> = parts
        .iter()
        .skip_while(|(n, _)| *n == 0)
        .take(2)
        .filter(|(n, _)| *n > 0)
        .map(|(n, unit)| format!("{n}{unit}"))
        .collect();
    if shown.is_empty() {
        "0s".to_owned()
    } else {
        shown.join(" ")
    }
}

async fn info(client: &Client) -> Result<(), Error> {
    let info = client
        .info()
        .await
        .map_err(|e| Error::admin("can't get the server's info", &e))?;
    if ui::json() {
        ui::emit(&record("server", &info));
        return Ok(());
    }
    ui::details(
        &[
            ("Version", info.version.clone()),
            ("Drive", info.drive.clone()),
            ("Account", info.account.clone()),
            ("Started", rfc3339(from_ms(info.started_ms))),
            ("Uptime", uptime(Duration::from_secs(info.uptime_seconds))),
        ],
        || Value::Null,
    );
    let mut table = ui::Table::new(&["JOB", "STEPS", "ITEMS", "LAST PROGRESS", "LAST ERROR"]);
    for (name, job) in &info.jobs {
        table.row(vec![
            name.clone(),
            job.steps.to_string(),
            job.items.to_string(),
            job.last_progress_ms
                .map(|ms| rfc3339(from_ms(ms)))
                .unwrap_or_default(),
            job.last_error.clone().unwrap_or_default(),
        ]);
    }
    table.print("No background jobs are running.");
    Ok(())
}

async fn config(client: &Client) -> Result<(), Error> {
    let config = client
        .config()
        .await
        .map_err(|e| Error::admin("can't get the server's configuration", &e))?;
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_owned();
    let kms = match &config.kms {
        teifs_client::KmsConfig::Keyring { path } => format!("keyring {path}"),
        teifs_client::KmsConfig::Transit { address } => format!("transit engine {address}"),
    };
    ui::details(
        &[
            ("Listen", config.listen.clone()),
            ("Domains", config.domains.join(", ")),
            ("Default layout", config.default_layout.clone()),
            ("Durability", config.durability.clone()),
            ("Key names", config.key_names.clone()),
            ("KMS", kms),
            (
                "Root key",
                match config.root_credentials.as_str() {
                    "drive" => "generated, in the drive (`teifs admin root-key rotate`)".to_owned(),
                    "given" => "given by environment, flags or a file".to_owned(),
                    other => other.to_owned(),
                },
            ),
            ("SSE-C allowed", yes_no(config.allow_sse_c)),
            ("Plain HTTP secure", yes_no(config.plain_http_is_secure)),
            ("Signature V2", yes_no(config.allow_sig_v2)),
            ("Legacy buckets", yes_no(config.legacy_bucket_defaults)),
            (
                "Upload expiry",
                config
                    .upload_expiry_seconds
                    .map_or_else(|| "never".to_owned(), |s| uptime(Duration::from_secs(s))),
            ),
            ("Max connections", config.max_connections.to_string()),
        ],
        || record("serverConfig", &config),
    );
    Ok(())
}

fn summary(export: &IamExport) -> String {
    let keys: usize = export.users.iter().map(|u| u.access_keys.len()).sum();
    format!(
        "{} users, {} groups, {} policies, {keys} access keys",
        export.users.len(),
        export.groups.len(),
        export.policies.len()
    )
}

async fn export(
    client: &Client,
    output: Option<&Path>,
    secrets: bool,
    force: bool,
) -> Result<(), Error> {
    if secrets && output.is_none() {
        return Err(
            Error::usage("an export with secrets goes to a file, never to the terminal")
                .with_hint("add --output FILE (written readable only by you)"),
        );
    }
    let export = client
        .export_iam(secrets)
        .await
        .map_err(|e| Error::admin("can't export IAM", &e))?;
    let Some(path) = output else {
        let text = if ui::json() {
            serde_json::to_string(&export)
        } else {
            serde_json::to_string_pretty(&export)
        };
        ui::raw(&text.map_err(|e| Error::general(e.to_string()))?);
        return Ok(());
    };
    let text = Zeroizing::new(
        serde_json::to_vec_pretty(&export).map_err(|e| Error::general(e.to_string()))?,
    );
    let written = if force {
        teifs_store::replace_private(path, &text)
    } else {
        teifs_store::create_private(path, &text)
    };
    written.map_err(|e| {
        let err = Error::general(format!("can't write {}: {e}", path.display()));
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error {
                kind: Kind::Conflict,
                ..err
            }
            .with_hint("choose another file, or add --force to replace it")
        } else {
            err
        }
    })?;
    ui::done(
        format!("Exported {} to {}", summary(&export), path.display()),
        || {
            json!({
                "type": "iamExport",
                "path": path,
                "secrets": secrets,
                "users": export.users.len(),
                "groups": export.groups.len(),
                "policies": export.policies.len(),
            })
        },
    );
    Ok(())
}

fn read_export(file: &Path) -> Result<IamExport, Error> {
    let bytes = if file == Path::new("-") {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| Error::general(format!("can't read standard input: {e}")))?;
        bytes
    } else {
        fs::read(file).map_err(|e| {
            let kind = if e.kind() == io::ErrorKind::NotFound {
                Kind::NotFound
            } else {
                Kind::General
            };
            Error::new(kind, format!("can't read {}: {e}", file.display()))
        })?
    };
    let bytes = Zeroizing::new(bytes);
    serde_json::from_slice(&bytes).map_err(|e| {
        Error::usage(format!("{} isn't an IAM export: {e}", file.display()))
            .with_hint("make one with `teifs admin iam export`")
    })
}

async fn import(client: &Client, file: &Path, adopt_account: bool) -> Result<(), Error> {
    let export = read_export(file)?;
    let report = client
        .import_iam(&export, adopt_account)
        .await
        .map_err(|e| Error::admin("can't import IAM", &e))?;
    if !report.keys_without_secrets.is_empty() {
        ui::warn(format!(
            "{} access keys weren't imported: the export has no secrets for them (export with \
             --secrets to bring them)",
            report.keys_without_secrets.len()
        ));
    }
    ui::done(
        format!(
            "Imported {} users, {} groups, {} roles, {} policies, {} OpenID Connect providers \
             and {} access keys into account {}",
            report.users,
            report.groups,
            report.roles,
            report.policies,
            report.oidc_providers,
            report.access_keys,
            report.account
        ),
        || record("iamImport", &report),
    );
    Ok(())
}

async fn rotate(mut aliases: Aliases, name: &str) -> Result<(), Error> {
    let (alias, origin) = alias(&aliases, name)?;
    let mut alias = alias.clone();
    if !ui::confirm(
        &format!(
            "Replace the root key of `{name}` ({})? The current key stops working at once.",
            alias.url
        ),
        "add --yes to replace it",
    )? {
        return Err(Error::general("nothing was changed").shown());
    }
    let rotated = client_for(&alias)?
        .rotate_root_key()
        .await
        .map_err(|e| Error::admin("can't replace the root key", &e))?;
    alias.access_key.clone_from(&rotated.access_key);
    alias.secret_key.clone_from(&rotated.secret_key);
    let updated = match origin {
        Origin::File => {
            aliases.set(name, alias).map_err(|e| {
                e.with_hint(
                    "the new key is in the server drive's .teifs/credentials.json: set the \
                     alias again from it",
                )
            })?;
            true
        }
        Origin::Env => {
            ui::warn(format!(
                "`{name}` is set by the environment, which still has the old key: the new one \
                 is in the server drive's .teifs/credentials.json"
            ));
            false
        }
    };
    ui::done(
        format!(
            "Replaced the root key: {}{}",
            rotated.access_key,
            if updated {
                format!(" (alias `{name}` updated)")
            } else {
                String::new()
            }
        ),
        || {
            json!({
                "type": "rootKey",
                "accessKey": rotated.access_key,
                "alias": name,
                "aliasUpdated": updated,
            })
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptimes_show_their_two_largest_units() {
        for (secs, text) in [
            (0, "0s"),
            (59, "59s"),
            (61, "1m 1s"),
            (3_600, "1h"),
            (90_061, "1d 1h"),
            (86_400 + 60, "1d"),
        ] {
            assert_eq!(uptime(Duration::from_secs(secs)), text, "{secs}");
        }
    }
}
