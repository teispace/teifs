//! `teifs admin service`: restart or stop a server, or hold its S3 requests for a while,
//! as `mc admin service` does (`MinIO`'s admin API, which TeiFS serves too).

use clap::Subcommand;
use serde_json::json;
use teifs_client::ServiceAction as Asked;

use super::{alias, client_for};
use crate::{client::alias::Aliases, error::Error, ui};

#[derive(Subcommand)]
pub enum ServiceAction {
    /// Restart the server: it finishes what it's answering, then starts again as it was
    /// started (with a binary that was replaced, the new one). Needs
    /// `admin:ServiceRestart`.
    Restart {
        /// The server's alias.
        alias: String,
        /// Only check the alias may restart it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Stop the server: it finishes what it's answering, then exits. Only whatever
    /// started it can start it again. Needs `admin:ServiceStop`.
    Stop {
        /// The server's alias.
        alias: String,
        /// Only check the alias may stop it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Hold the server's S3 requests (not its admin API's) until `unfreeze`: each
    /// freeze needs its own. A restart or stop lets them go. Needs
    /// `admin:ServiceFreeze`.
    Freeze {
        /// The server's alias.
        alias: String,
    },
    /// Undo a `freeze`. Needs `admin:ServiceFreeze`.
    Unfreeze {
        /// The server's alias.
        alias: String,
    },
}

pub async fn run(aliases: &Aliases, action: ServiceAction) -> Result<(), Error> {
    let (name, asked, dry_run) = match action {
        ServiceAction::Restart { alias, dry_run } => (alias, Asked::Restart, dry_run),
        ServiceAction::Stop { alias, dry_run } => (alias, Asked::Stop, dry_run),
        ServiceAction::Freeze { alias } => (alias, Asked::Freeze, false),
        ServiceAction::Unfreeze { alias } => (alias, Asked::Unfreeze, false),
    };
    if asked == Asked::Stop
        && !dry_run
        && !ui::confirm(
            &format!("Stop the server at {name}? Only whatever started it can start it again."),
            "add --yes to stop it without asking",
        )?
    {
        return Ok(());
    }
    let client = client_for(alias(aliases, &name)?.0)?;
    client
        .service(asked, dry_run)
        .await
        .map_err(|e| Error::admin(format!("can't {} the server", asked.name()), &e))?;
    let message = match (asked, dry_run) {
        (Asked::Restart | Asked::Stop, true) => {
            format!("{name} may {} the server (nothing was done)", asked.name())
        }
        (Asked::Restart, false) => format!("The server at {name} is restarting"),
        (Asked::Stop, false) => format!("The server at {name} is stopping"),
        (Asked::Freeze, _) => format!("The server at {name} holds S3 requests until unfrozen"),
        (Asked::Unfreeze, _) => format!("Undid a freeze of the server at {name}"),
    };
    ui::done(
        message,
        || json!({"type": "service", "alias": name, "action": asked.name(), "dryRun": dry_run}),
    );
    Ok(())
}
