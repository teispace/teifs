//! `teifs admin kms`: a server's KMS and its keys, over the network, as `mc admin kms`
//! does (`MinIO`'s KMS API, which TeiFS serves too). `teifs key` manages a KMS
//! directly instead.

use clap::Subcommand;
use serde_json::json;

use super::{alias, client_for};
use crate::{client::alias::Aliases, error::Error, ui};

#[derive(Subcommand)]
pub enum KmsAction {
    /// The server's KMS: its kind, default key, and whether each endpoint answers.
    /// Needs `kms:Status`.
    Status {
        /// The server's alias.
        alias: String,
    },
    /// The server's KMS keys.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
}

#[derive(Subcommand)]
pub enum KeyAction {
    /// Create a key, for SSE-KMS (`x-amz-server-side-encryption-aws-kms-key-id`).
    /// Needs `kms:CreateKey` on it (`arn:minio:kms:::NAME`).
    Create {
        /// The server's alias.
        alias: String,
        /// The key's name.
        name: String,
    },
    /// List the keys whose names start with PREFIX (all by default) that the alias
    /// may list. Needs `kms:ListKeys`.
    List {
        /// The server's alias.
        alias: String,
        /// Only keys whose names start with this.
        #[arg(default_value = "")]
        prefix: String,
    },
    /// Check a key (the default key by default) seals a new data key and unseals it
    /// again. Needs `kms:KeyStatus` on it.
    Status {
        /// The server's alias.
        alias: String,
        /// The key's name.
        name: Option<String>,
    },
}

pub async fn run(aliases: &Aliases, action: KmsAction) -> Result<(), Error> {
    match action {
        KmsAction::Status { alias: name } => {
            let client = client_for(alias(aliases, &name)?.0)?;
            let status = client
                .kms_status()
                .await
                .map_err(|e| Error::admin("can't read the server's KMS status", &e))?;
            let endpoints = status
                .endpoints
                .iter()
                .map(|(endpoint, state)| format!("{endpoint} ({state})"))
                .collect::<Vec<_>>()
                .join(", ");
            ui::details(
                &[
                    ("KMS", status.name.clone()),
                    ("Default key", status.default_key.clone()),
                    ("Endpoints", endpoints),
                ],
                || {
                    json!({
                        "type": "kmsStatus",
                        "alias": name,
                        "name": status.name,
                        "defaultKey": status.default_key,
                        "endpoints": status.endpoints,
                    })
                },
            );
        }
        KmsAction::Key {
            action: KeyAction::Create { alias: name, name: key },
        } => {
            let client = client_for(alias(aliases, &name)?.0)?;
            client
                .create_kms_key(&key)
                .await
                .map_err(|e| Error::admin(format!("can't create key {key}"), &e))?;
            ui::done(format!("Created key {key} at {name}"), || {
                json!({"type": "kmsKey", "alias": name, "name": key})
            });
        }
        KmsAction::Key {
            action: KeyAction::List { alias: name, prefix },
        } => {
            let client = client_for(alias(aliases, &name)?.0)?;
            let keys = client
                .kms_keys(&prefix)
                .await
                .map_err(|e| Error::admin("can't list the server's KMS keys", &e))?;
            let mut table = ui::Table::new(&["NAME", "CREATED"]);
            let mut records = Vec::new();
            for key in keys {
                records.push(json!({"type": "kmsKey", "name": key.name, "createdAt": key.created_at}));
                table.row(vec![key.name, key.created_at]);
            }
            ui::rows(&table, &records, "No keys.");
        }
        KmsAction::Key {
            action: KeyAction::Status { alias: name, name: key },
        } => {
            let client = client_for(alias(aliases, &name)?.0)?;
            let status = client
                .kms_key_status(key.as_deref())
                .await
                .map_err(|e| Error::admin("can't check the key", &e))?;
            let outcome = |err: &Option<String>| err.clone().unwrap_or_else(|| "ok".to_owned());
            let unsealing = if status.encryption_error.is_some() {
                "not tried".to_owned()
            } else {
                outcome(&status.decryption_error)
            };
            ui::details(
                &[
                    ("Key", status.key.clone()),
                    ("Sealing", outcome(&status.encryption_error)),
                    ("Unsealing", unsealing),
                ],
                || {
                    json!({
                        "type": "kmsKeyStatus",
                        "name": status.key,
                        "encryptionError": status.encryption_error,
                        "decryptionError": status.decryption_error,
                    })
                },
            );
            if status.encryption_error.is_some() || status.decryption_error.is_some() {
                return Err(Error::general(format!(
                    "key {} doesn't seal and unseal data keys",
                    status.key
                )));
            }
        }
    }
    Ok(())
}
