//! `teifs admin config`: how a server was started, and `MinIO`'s key-value settings it
//! keeps on its drive (`mc admin config get|set|reset|history|restore|export|import`).
//! What's set takes effect when the server starts again (`teifs admin service restart`).

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use clap::Subcommand;
use serde_json::json;
use teifs_client::Zeroizing;

use super::{alias, client_for, read_file, write_file};
use crate::{client::alias::Aliases, error::Error, ui};

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show a sub-system's settings (`identity_ldap`, `identity_openid[:NAME]`,
    /// `identity_plugin`; every one without it), never their secrets.
    Get {
        /// The server's alias.
        alias: String,
        /// The sub-system, and its target after a colon.
        #[arg(default_value = "")]
        key: String,
    },
    /// Set a sub-system's keys: `identity_ldap server_addr=ldap.example.com:636 …`.
    /// Takes effect when the server starts again; a setting it wouldn't start with is
    /// refused.
    Set {
        /// The server's alias.
        alias: String,
        /// The sub-system, and its target after a colon.
        target: String,
        /// The keys, as KEY=VALUE.
        #[arg(required = true, value_name = "KEY=VALUE")]
        keys: Vec<String>,
    },
    /// Reset a sub-system's keys to their defaults, or all of a target's.
    Reset {
        /// The server's alias.
        alias: String,
        /// The sub-system, and its target after a colon.
        target: String,
        /// The keys to reset; all of them without any.
        keys: Vec<String>,
    },
    /// List the keys a sub-system takes (the sub-systems, without one).
    Keys {
        /// The server's alias.
        alias: String,
        /// The sub-system.
        #[arg(default_value = "")]
        subsystem: String,
        /// Only this key.
        #[arg(default_value = "")]
        key: String,
        /// Name the keys by their environment variables.
        #[arg(long)]
        env: bool,
    },
    /// List the newest changes, which `restore` puts back.
    History {
        /// The server's alias.
        alias: String,
        /// How many (0 for all).
        #[arg(long, default_value_t = 10)]
        count: usize,
    },
    /// Set a change's keys again; the change leaves the history.
    Restore {
        /// The server's alias.
        alias: String,
        /// The change, as `history` lists it.
        id: String,
    },
    /// Forget a change, or every one with `all`.
    ClearHistory {
        /// The server's alias.
        alias: String,
        /// The change, as `history` lists it, or `all`.
        id: String,
    },
    /// Write every setting, secrets included, to a file readable only by you.
    Export {
        /// The server's alias.
        alias: String,
        /// The file to write.
        #[arg(short, long)]
        output: PathBuf,
        /// Replace the file if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Replace every setting with an export's.
    Import {
        /// The server's alias.
        alias: String,
        /// The export: a file, or `-` for standard input.
        file: PathBuf,
    },
}

pub async fn run(aliases: &Aliases, action: ConfigAction) -> Result<(), Error> {
    match action {
        ConfigAction::Get { alias: name, key } => get(aliases, &name, &key).await?,
        ConfigAction::Set {
            alias: name,
            target,
            keys,
        } => {
            client(aliases, &name)?
                .set_config_kv(&line(&target, &keys))
                .await
                .map_err(|e| Error::admin(format!("can't set {target}"), &e))?;
            changed(&name, "configSet", &target);
        }
        ConfigAction::Reset {
            alias: name,
            target,
            keys,
        } => {
            client(aliases, &name)?
                .reset_config_kv(
                    &std::iter::once(&target)
                        .chain(&keys)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" "),
                )
                .await
                .map_err(|e| Error::admin(format!("can't reset {target}"), &e))?;
            changed(&name, "configReset", &target);
        }
        ConfigAction::Keys {
            alias: name,
            subsystem,
            key,
            env,
        } => keys(aliases, &name, &subsystem, &key, env).await?,
        ConfigAction::History { alias: name, count } => history(aliases, &name, count).await?,
        ConfigAction::Restore { alias: name, id } => {
            client(aliases, &name)?
                .restore_config(&id)
                .await
                .map_err(|e| Error::admin(format!("can't put change {id} back"), &e))?;
            changed(&name, "configRestore", &id);
        }
        ConfigAction::ClearHistory { alias: name, id } => {
            client(aliases, &name)?
                .clear_config_history(&id)
                .await
                .map_err(|e| Error::admin("can't forget the change", &e))?;
            let what = if id == "all" {
                "every change".to_owned()
            } else {
                format!("change {id}")
            };
            ui::done(
                format!("Forgot {what} at {name}"),
                || json!({"type": "configHistoryCleared", "alias": name, "id": id}),
            );
        }
        ConfigAction::Export {
            alias: name,
            output,
            force,
        } => export(aliases, &name, &output, force).await?,
        ConfigAction::Import { alias: name, file } => {
            let bytes = read_file(&file)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Error::usage(format!("{} isn't text", file.display())))?;
            client(aliases, &name)?
                .import_config(text)
                .await
                .map_err(|e| Error::admin("can't import the settings", &e))?;
            changed(&name, "configImport", &file.display().to_string());
        }
    }
    Ok(())
}

async fn get(aliases: &Aliases, name: &str, key: &str) -> Result<(), Error> {
    let client = client(aliases, name)?;
    let failed =
        |e: teifs_client::ClientError| Error::admin("can't read the server's settings", &e);
    // Every sub-system the server has, without one, as `mc admin config get` lists
    // them.
    let keys = if key.is_empty() {
        let help = client.config_help("", "", false).await.map_err(failed)?;
        help.keys_help.into_iter().map(|k| k.key).collect()
    } else {
        vec![key.to_owned()]
    };
    let mut text = String::new();
    for key in &keys {
        text.push_str(&client.config_kv(key).await.map_err(failed)?);
    }
    if ui::json() {
        ui::emit(&json!({"type": "configKv", "alias": name, "key": key, "text": text}));
    } else {
        ui::document(&text);
    }
    Ok(())
}

async fn keys(
    aliases: &Aliases,
    name: &str,
    subsystem: &str,
    key: &str,
    env: bool,
) -> Result<(), Error> {
    let help = client(aliases, name)?
        .config_help(subsystem, key, env)
        .await
        .map_err(|e| Error::admin("can't read the server's settings", &e))?;
    let mut table = ui::Table::new(&["KEY", "TYPE", "OPTIONAL", "DESCRIPTION"]);
    let mut records = Vec::new();
    for key in help.keys_help {
        let optional = if key.optional { "yes" } else { "no" };
        records.push(json!({
            "type": "configKey",
            "subsystem": help.sub_sys,
            "key": key.key,
            "kind": key.kind,
            "optional": key.optional,
            "description": key.description,
        }));
        table.row(vec![
            key.key,
            key.kind,
            optional.to_owned(),
            key.description,
        ]);
    }
    ui::rows(&table, &records, "No keys.");
    Ok(())
}

async fn history(aliases: &Aliases, name: &str, count: usize) -> Result<(), Error> {
    let changes = client(aliases, name)?
        .config_history(count)
        .await
        .map_err(|e| Error::admin("can't list the server's changes", &e))?;
    // What each change set, by target: its values may be secrets.
    let mut table = ui::Table::new(&["ID", "MADE", "SET"]);
    let mut records = Vec::new();
    for change in changes {
        let targets = targets(&change.data);
        records.push(json!({
            "type": "configChange",
            "id": change.restore_id,
            "created": change.create_time,
            "targets": targets,
        }));
        table.row(vec![
            change.restore_id,
            change.create_time,
            targets.join(", "),
        ]);
    }
    ui::rows(&table, &records, "No changes.");
    Ok(())
}

fn client(aliases: &Aliases, name: &str) -> Result<teifs_client::Client, Error> {
    client_for(alias(aliases, name)?.0)
}

/// `TARGET KEY=VALUE…`, with values that have spaces quoted so they stay one value.
fn line(target: &str, keys: &[String]) -> String {
    let mut line = target.to_owned();
    for pair in keys {
        line.push(' ');
        match pair.split_once('=') {
            Some((key, value))
                if value.contains(char::is_whitespace) && !value.starts_with('"') =>
            {
                let _ = write!(line, "{key}=\"{value}\"");
            }
            _ => line.push_str(pair),
        }
    }
    line
}

/// The targets a change's lines set (`identity_ldap`, `identity_openid:NAME`).
fn targets(lines: &str) -> Vec<String> {
    lines
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|word| !word.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Says a change was kept, and when it takes effect.
fn changed(name: &str, kind: &str, what: &str) {
    ui::done(
        format!("Changed {what} at {name}"),
        || json!({"type": kind, "alias": name, "target": what, "restartNeeded": true}),
    );
    ui::note(format!(
        "It takes effect when the server starts again: `teifs admin service restart {name}`"
    ));
}

async fn export(aliases: &Aliases, name: &str, output: &Path, force: bool) -> Result<(), Error> {
    let text = client(aliases, name)?
        .export_config()
        .await
        .map_err(|e| Error::admin("can't export the settings", &e))?;
    write_file(
        output,
        Zeroizing::new(text.as_bytes().to_vec()).as_slice(),
        force,
    )?;
    ui::done(
        format!("Exported {name}'s settings to {}", output.display()),
        || json!({"type": "configExport", "alias": name, "path": output}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_with_spaces_stay_one_value() {
        let keys = [
            "server_addr=a:636".to_owned(),
            "lookup_bind_dn=cn=admin, dc=example".to_owned(),
            "x=\"q r\"".to_owned(),
        ];
        assert_eq!(
            line("identity_ldap", &keys),
            "identity_ldap server_addr=a:636 lookup_bind_dn=\"cn=admin, dc=example\" x=\"q r\""
        );
        assert_eq!(
            targets("identity_ldap server_addr=a\n# comment\nidentity_openid:k client_id=x"),
            ["identity_ldap", "identity_openid:k"]
        );
    }
}
