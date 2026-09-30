//! `teifs admin prometheus generate`: a Prometheus scrape configuration for a server's
//! metrics, with a bearer token signed by the alias's access key, as
//! `mc admin prometheus generate` makes one for `MinIO`.

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Subcommand;
use serde_json::json;

use super::{alias, write_file};
use crate::{
    client::alias::Aliases,
    error::{Error, Kind},
    ui,
    units::parse_duration,
};

#[derive(Subcommand)]
pub enum PrometheusAction {
    /// Print a scrape configuration for the server's metrics (`/.teifs/metrics`), with a
    /// bearer token signed by the alias's access key, whose policies need
    /// `teifs:GetMetrics`. Deleting or deactivating the key revokes the token.
    Generate {
        /// The server's alias.
        alias: String,
        /// How long the token is good for (`90d`); without it, until the key is revoked.
        #[arg(long, value_parser = parse_duration)]
        expires: Option<Duration>,
        /// Write the token to this file (owner-only) and have the configuration read it
        /// from there (`credentials_file`) rather than hold it.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Replace the token file if it exists.
        #[arg(long, requires = "token_file")]
        force: bool,
    },
}

pub fn run(aliases: &Aliases, action: PrometheusAction) -> Result<(), Error> {
    let PrometheusAction::Generate {
        alias: name,
        expires,
        token_file,
        force,
    } = action;
    let (alias, _) = alias(aliases, &name)?;
    if alias.session_token.is_some() {
        return Err(Error::usage(format!(
            "`{name}` uses temporary credentials, which can't sign a token that outlives them"
        ))
        .with_hint("use an alias with a user's access key"));
    }
    let expires = expires
        .map(|duration| {
            let at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .saturating_add(duration);
            i64::try_from(at.as_secs()).map_err(|_| Error::usage("that's too long"))
        })
        .transpose()?;
    let token = teifs_iam::metrics_token(&alias.access_key, &alias.secret_key, expires);
    let (scheme, target) = alias
        .url
        .split_once("://")
        .ok_or_else(|| Error::new(Kind::General, format!("`{name}` has no URL scheme")))?;
    let credentials = match &token_file {
        Some(path) => {
            write_file(path, token.as_bytes(), force)?;
            let path = std::path::absolute(path).unwrap_or_else(|_| path.clone());
            format!("credentials_file: {}", yaml_string(&path.to_string_lossy()))
        }
        None => format!("credentials: {}", yaml_string(&token)),
    };
    let config = format!(
        "scrape_configs:\n\
         \x20 - job_name: teifs\n\
         \x20   metrics_path: {}\n\
         \x20   scheme: {scheme}\n\
         \x20   authorization:\n\
         \x20     {credentials}\n\
         \x20   static_configs:\n\
         \x20     - targets: [{}]\n",
        teifs_types::admin::METRICS_PATH,
        yaml_string(target.trim_end_matches('/')),
    );
    if ui::json() {
        ui::emit(&json!({
            "type": "prometheusConfig",
            "config": config,
            "expires": expires,
        }));
    } else {
        ui::document(&config);
    }
    Ok(())
}

/// `text` as a double-quoted YAML string.
fn yaml_string(text: &str) -> String {
    serde_json::to_string(text).expect("strings serialize")
}
