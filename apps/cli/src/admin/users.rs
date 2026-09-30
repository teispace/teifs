//! `teifs admin user`: IAM users for people without the AWS CLI — a user with a policy
//! and an access key in one step. It speaks AWS's IAM API, as `aws iam` does. A new key's
//! secret goes into an alias or an owner-only file, and to the terminal only when asked
//! for with `--output -`.

use std::path::{Path, PathBuf};

use aws_sdk_iam::Client;
use clap::{Args, Subcommand};
use serde_json::json;
use teifs_client::Zeroizing;

use super::{
    alias,
    policy::{POLICY_NAME, PolicyArgs},
};
use crate::{
    client::alias::{Alias, Aliases, check_name},
    error::{Error, Kind},
    ui,
    units::{date, from_ms},
};

#[derive(Subcommand)]
pub enum UserAction {
    /// Add a user with a policy and an access key.
    Add {
        /// The server's alias.
        alias: String,
        /// The user's name.
        name: String,
        #[command(flatten)]
        policy: PolicyArgs,
        #[command(flatten)]
        key: KeyOutput,
    },
    /// List the users with their access keys and policies.
    Ls {
        /// The server's alias.
        alias: String,
    },
    /// Delete a user with its access keys, policies and group memberships (asks first).
    Rm {
        /// The server's alias.
        alias: String,
        /// The user's name.
        name: String,
    },
    /// Replace the policy `user add` gave a user.
    Policy {
        /// The server's alias.
        alias: String,
        /// The user's name.
        name: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// A user's access keys.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
}

#[derive(Subcommand)]
pub enum KeyAction {
    /// Add an access key (a user has at most two).
    Add {
        /// The server's alias.
        alias: String,
        /// The user's name.
        name: String,
        #[command(flatten)]
        key: KeyOutput,
    },
    /// List a user's access keys (never their secrets).
    Ls {
        /// The server's alias.
        alias: String,
        /// The user's name.
        name: String,
    },
    /// Delete an access key: requests signed with it fail from now on.
    Rm {
        /// The server's alias.
        alias: String,
        /// The user's name.
        name: String,
        /// The access key's id.
        key: String,
    },
}

/// Where a new access key goes.
#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct KeyOutput {
    /// Save it as a new alias of this name, for the same server.
    #[arg(long, value_name = "ALIAS")]
    save_alias: Option<String>,
    /// Write it to this file (readable only by you), or to standard output with `-`.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

impl UserAction {
    fn alias(&self) -> &str {
        match self {
            Self::Add { alias, .. }
            | Self::Ls { alias }
            | Self::Rm { alias, .. }
            | Self::Policy { alias, .. }
            | Self::Key {
                action:
                    KeyAction::Add { alias, .. }
                    | KeyAction::Ls { alias, .. }
                    | KeyAction::Rm { alias, .. },
            } => alias,
        }
    }
}

pub async fn run(mut aliases: Aliases, action: UserAction) -> Result<(), Error> {
    let server = alias(&aliases, action.alias())?.0.clone();
    let iam = super::iam(&server);
    match action {
        UserAction::Add {
            name, policy, key, ..
        } => {
            // Everything that can be checked here is, before anything changes.
            let document = policy.document()?;
            key.check(&aliases)?;
            let new = NewUser {
                policy: &policy.policy,
                document: &document,
            };
            add_user(&iam, &server, &name, &new, &key, &mut aliases).await?;
            Ok(())
        }
        UserAction::Ls { .. } => list(&iam).await,
        UserAction::Rm { name, .. } => {
            let keys = key_ids(&iam, &name).await?;
            if !ui::confirm(
                &format!(
                    "Delete user {name} and its {} access keys? Requests signed with them fail \
                     from now on.",
                    keys.len()
                ),
                "add --yes to delete it",
            )? {
                return Err(Error::general("nothing was deleted").shown());
            }
            delete_user(&iam, &name, &keys).await?;
            ui::done(
                format!("Deleted user {name}"),
                || json!({"type": "userDeleted", "user": name, "accessKeys": keys}),
            );
            Ok(())
        }
        UserAction::Policy { name, policy, .. } => {
            put_policy(&iam, &name, &policy.document()?).await?;
            ui::done(
                format!("Gave {name} the {} policy", policy.policy),
                || json!({"type": "userPolicy", "user": name, "policy": policy.policy}),
            );
            Ok(())
        }
        UserAction::Key { action } => match action {
            KeyAction::Add { name, key, .. } => {
                key.check(&aliases)?;
                add_key(&iam, &server, &name, &key, &mut aliases, None).await
            }
            KeyAction::Ls { name, .. } => list_keys(&iam, &name).await,
            KeyAction::Rm { name, key, .. } => {
                iam.delete_access_key()
                    .user_name(&name)
                    .access_key_id(&key)
                    .send()
                    .await
                    .map_err(|e| Error::s3(format_args!("can't delete access key {key}"), &e))?;
                ui::done(
                    format!("Deleted {name}'s access key {key}"),
                    || json!({"type": "accessKeyDeleted", "user": name, "accessKey": key}),
                );
                Ok(())
            }
        },
    }
}

impl KeyOutput {
    /// Refuses a place the key couldn't go, before anything changes.
    fn check(&self, aliases: &Aliases) -> Result<(), Error> {
        if let Some(name) = &self.save_alias {
            check_name(name).map_err(Error::usage)?;
            if aliases.get(name).is_some() {
                return Err(Error::new(
                    Kind::Conflict,
                    format!("there's already an alias `{name}`"),
                )
                .with_hint("choose another name"));
            }
        }
        if let Some(path) = self.file()
            && path.exists()
        {
            return Err(
                Error::new(Kind::Conflict, format!("{} already exists", path.display()))
                    .with_hint("choose another file"),
            );
        }
        Ok(())
    }

    /// The file to write, when it's not standard output.
    fn file(&self) -> Option<&Path> {
        self.output.as_deref().filter(|p| *p != Path::new("-"))
    }
}

/// The policy a new user gets: its name as given, and its document.
struct NewUser<'a> {
    policy: &'a str,
    document: &'a str,
}

/// Creates a user with its policy and a key, or, when a step fails, nothing.
async fn add_user(
    iam: &Client,
    server: &Alias,
    name: &str,
    new: &NewUser<'_>,
    key: &KeyOutput,
    aliases: &mut Aliases,
) -> Result<(), Error> {
    iam.create_user()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(format_args!("can't add user {name}"), &e))?;
    let rest = async {
        put_policy(iam, name, new.document).await?;
        add_key(iam, server, name, key, aliases, Some(new.policy)).await
    };
    if let Err(err) = rest.await {
        let undone = match key_ids(iam, name).await {
            Ok(keys) => delete_user(iam, name, &keys).await,
            Err(e) => Err(e),
        };
        if let Err(e) = undone {
            ui::warn(format!(
                "user {name} was added but not finished: {}",
                e.message
            ));
        }
        return Err(err);
    }
    Ok(())
}

async fn put_policy(iam: &Client, name: &str, document: &str) -> Result<(), Error> {
    iam.put_user_policy()
        .user_name(name)
        .policy_name(POLICY_NAME)
        .policy_document(document)
        .send()
        .await
        .map_err(|e| Error::s3(format_args!("can't set {name}'s policy"), &e))?;
    Ok(())
}

/// Creates an access key for `name` and puts it where `output` says. If it can't be put
/// there, the key is deleted again: a key whose secret nobody has is only a risk.
/// `policy` is the new user's, when the key is its first.
async fn add_key(
    iam: &Client,
    server: &Alias,
    name: &str,
    output: &KeyOutput,
    aliases: &mut Aliases,
    policy: Option<&str>,
) -> Result<(), Error> {
    let created = iam
        .create_access_key()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(format_args!("can't add an access key for {name}"), &e))?;
    let key = created
        .access_key()
        .ok_or_else(|| Error::general("the server answered without an access key"))?;
    let id = key.access_key_id();
    let secret = Zeroizing::new(key.secret_access_key().to_owned());
    let added = match policy {
        Some(policy) => format!("Added user {name} with the {policy} policy and access key {id}"),
        None => format!("Added access key {id} for {name}"),
    };
    let saved_to = match save_key(server, name, id, &secret, output, aliases) {
        Ok(Some(place)) => place,
        Ok(None) => {
            ui::note(added);
            return Ok(());
        }
        Err(err) => {
            let _ = iam
                .delete_access_key()
                .user_name(name)
                .access_key_id(id)
                .send()
                .await;
            return Err(err);
        }
    };
    ui::done(format!("{added}, in {saved_to}"), || {
        json!({
            "type": "accessKey",
            "user": name,
            "accessKey": id,
            "savedTo": saved_to,
            "policy": policy,
        })
    });
    Ok(())
}

/// Puts a new key where `output` says: where it went, or `None` when it was printed.
fn save_key(
    server: &Alias,
    name: &str,
    id: &str,
    secret: &str,
    output: &KeyOutput,
    aliases: &mut Aliases,
) -> Result<Option<String>, Error> {
    if let Some(alias_name) = &output.save_alias {
        // A user's own long-term key: none of the server alias's session.
        let alias = Alias {
            access_key: id.to_owned(),
            secret_key: secret.to_owned(),
            session_token: None,
            expires: None,
            ..server.clone()
        };
        aliases.set(alias_name, alias)?;
        return Ok(Some(format!("alias `{alias_name}`")));
    }
    let record = Zeroizing::new(
        json!({
            "type": "accessKey",
            "user": name,
            "endpoint": server.url,
            "region": server.region,
            "accessKey": id,
            "secretKey": secret,
        })
        .to_string(),
    );
    let Some(path) = output.file() else {
        // `--output -`: the one place a secret goes to standard output, as asked.
        ui::document(&record);
        return Ok(None);
    };
    teifs_store::create_private(path, record.as_bytes())
        .map_err(|e| Error::general(format!("can't write {}: {e}", path.display())))?;
    Ok(Some(path.display().to_string()))
}

async fn key_ids(iam: &Client, name: &str) -> Result<Vec<String>, Error> {
    let keys = iam
        .list_access_keys()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(format_args!("can't list {name}'s access keys"), &e))?;
    Ok(keys
        .access_key_metadata()
        .iter()
        .filter_map(|k| k.access_key_id().map(str::to_owned))
        .collect())
}

/// The names of a user's policies: inline, then attached.
async fn policy_names(iam: &Client, name: &str) -> Result<Vec<String>, Error> {
    let what = format!("can't list {name}'s policies");
    let inline = iam
        .list_user_policies()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(&what, &e))?;
    let attached = iam
        .list_attached_user_policies()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(&what, &e))?;
    Ok(inline
        .policy_names()
        .iter()
        .cloned()
        .chain(
            attached
                .attached_policies()
                .iter()
                .filter_map(|p| p.policy_name().map(str::to_owned)),
        )
        .collect())
}

/// Deletes a user and first what IAM wants gone before it: keys, policies, groups.
async fn delete_user(iam: &Client, name: &str, keys: &[String]) -> Result<(), Error> {
    let what = format!("can't delete user {name}");
    for key in keys {
        iam.delete_access_key()
            .user_name(name)
            .access_key_id(key)
            .send()
            .await
            .map_err(|e| Error::s3(&what, &e))?;
    }
    let inline = iam
        .list_user_policies()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(&what, &e))?;
    for policy in inline.policy_names() {
        iam.delete_user_policy()
            .user_name(name)
            .policy_name(policy)
            .send()
            .await
            .map_err(|e| Error::s3(&what, &e))?;
    }
    let attached = iam
        .list_attached_user_policies()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(&what, &e))?;
    for arn in attached
        .attached_policies()
        .iter()
        .filter_map(|p| p.policy_arn())
    {
        iam.detach_user_policy()
            .user_name(name)
            .policy_arn(arn)
            .send()
            .await
            .map_err(|e| Error::s3(&what, &e))?;
    }
    let groups = iam
        .list_groups_for_user()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(&what, &e))?;
    for group in groups.groups() {
        iam.remove_user_from_group()
            .user_name(name)
            .group_name(group.group_name())
            .send()
            .await
            .map_err(|e| Error::s3(&what, &e))?;
    }
    iam.delete_user()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(&what, &e))?;
    Ok(())
}

async fn list(iam: &Client) -> Result<(), Error> {
    let users = iam
        .list_users()
        .into_paginator()
        .items()
        .send()
        .collect::<Result<Vec<_>, _>>()
        .await
        .map_err(|e| Error::s3("can't list users", &e))?;
    let mut table = ui::Table::new(&["USER", "KEYS", "POLICIES", "CREATED"]);
    let mut records = Vec::with_capacity(users.len());
    for user in &users {
        let name = user.user_name();
        let (keys, policies) = tokio::try_join!(key_ids(iam, name), policy_names(iam, name))?;
        let created = user.create_date().to_millis().unwrap_or_default();
        table.row(vec![
            name.to_owned(),
            keys.len().to_string(),
            policies.join(", "),
            date(from_ms(created)),
        ]);
        records.push(json!({
            "type": "user",
            "name": name,
            "arn": user.arn(),
            "accessKeys": keys,
            "policies": policies,
            "createdMs": created,
        }));
    }
    ui::rows(
        &table,
        &records,
        "No users yet. Add one with `teifs admin user add`.",
    );
    Ok(())
}

async fn list_keys(iam: &Client, name: &str) -> Result<(), Error> {
    let keys = iam
        .list_access_keys()
        .user_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(format_args!("can't list {name}'s access keys"), &e))?;
    let mut table = ui::Table::new(&["ACCESS KEY", "STATUS", "CREATED"]);
    let mut records = Vec::new();
    for key in keys.access_key_metadata() {
        let id = key.access_key_id().unwrap_or_default();
        let status = key
            .status()
            .map(aws_sdk_iam::types::StatusType::as_str)
            .unwrap_or_default();
        let created = key
            .create_date()
            .and_then(|d| d.to_millis().ok())
            .unwrap_or_default();
        table.row(vec![
            id.to_owned(),
            status.to_owned(),
            date(from_ms(created)),
        ]);
        records.push(json!({
            "type": "accessKey", "user": name, "accessKey": id, "status": status,
            "createdMs": created,
        }));
    }
    ui::rows(&table, &records, &format!("{name} has no access keys."));
    Ok(())
}
