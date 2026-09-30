//! The client commands.

use std::{collections::BTreeMap, path::Path, time::Duration};

use aws_sdk_s3::{
    Client,
    operation::head_object::HeadObjectOutput,
    presigning::PresigningConfig,
    types::{BucketLocationConstraint, CreateBucketConfiguration, Delete, ObjectIdentifier},
};
use futures::{StreamExt, TryStreamExt, stream};
use serde_json::json;
use teifs_types::caps::MAX_CONTENT_LENGTH;

use super::{
    AliasAction, Command, Error, Kind, SetAlias,
    alias::{self, Alias, Aliases, Origin},
    listing,
    sse::{self, customer_key},
    target::{Remote, Target, folder_prefix},
    transfer::Object,
};
use crate::{
    ui,
    units::{date, rfc3339, size},
};

/// The longest a presigned link can work (Signature V4's limit).
const MAX_PRESIGN: Duration = Duration::from_hours(7 * 24);
/// The most keys one `DeleteObjects` request takes.
const DELETE_BATCH: usize = 1000;

pub async fn run(command: Command) -> Result<(), Error> {
    let mut aliases = Aliases::load()?;
    let remote = |text: &str, what: &str| Target::parse(text, &aliases)?.remote(what);
    match command {
        Command::Alias { action } => alias_command(action, &mut aliases).await,
        Command::Ls {
            target,
            recursive,
            versions,
        } => ls(remote(&target, "ls")?, recursive, versions).await,
        Command::Mb {
            target,
            layout,
            ignore_existing,
            with_lock,
        } => mb(remote(&target, "mb")?, layout, ignore_existing, with_lock).await,
        Command::Rb { target, force } => rb(remote(&target, "rb")?, force).await,
        Command::Cp(args) => {
            sse::use_rules(sse::Rules::read(&args.enc, &aliases)?);
            super::copy::copy(args, false, &aliases).await
        }
        Command::Mv(args) => {
            sse::use_rules(sse::Rules::read(&args.enc, &aliases)?);
            super::copy::copy(args, true, &aliases).await
        }
        Command::Rm {
            targets,
            recursive,
            force,
            version_id,
            versions,
            bypass,
        } => {
            if bypass && version_id.is_none() && !versions {
                return Err(Error::usage(
                    "--bypass removes locked versions: use it with --version-id or --versions",
                ));
            }
            for target in &targets {
                let target = remote(target, "rm")?;
                match (&version_id, versions) {
                    (Some(id), _) => super::versions::rm_version(target, id, bypass).await?,
                    (None, true) => {
                        super::versions::rm_versions(target, recursive, force, bypass).await?;
                    }
                    (None, false) => rm(target, recursive, force).await?,
                }
            }
            Ok(())
        }
        Command::Cat {
            targets,
            version_id,
            keys,
        } => {
            sse::use_rules(sse::Rules::read(&keys.into(), &aliases)?);
            for target in &targets {
                cat(remote(target, "cat")?, version_id.as_deref()).await?;
            }
            Ok(())
        }
        Command::Stat {
            target,
            version_id,
            keys,
        } => {
            sse::use_rules(sse::Rules::read(&keys.into(), &aliases)?);
            stat(remote(&target, "stat")?, version_id.as_deref()).await
        }
        Command::Version { action } => super::versions::versioning(action, &aliases).await,
        Command::Retention { action } => super::lock::retention(action, &aliases).await,
        Command::Legalhold { action } => super::lock::legal_hold(action, &aliases).await,
        Command::Ilm { action } => super::ilm::ilm(action, &aliases).await,
        Command::Event { action } => super::event::event(action, &aliases).await,
        Command::Watch(args) => super::watch::run(&aliases, args).await,
        Command::Encrypt { action } => super::encrypt::encrypt(action, &aliases).await,
        Command::Logging { action } => super::logging::logging(action, &aliases).await,
        Command::Website { action } => super::website::website(action, &aliases).await,
        Command::Presign {
            target,
            expires,
            put,
            max_size,
        } => presign(remote(&target, "presign")?, expires, put, max_size).await,
        Command::Mirror {
            source,
            destination,
            remove,
            dry_run,
            transfer,
            enc,
        } => {
            sse::use_rules(sse::Rules::read(&enc, &aliases)?);
            let source = Target::parse(&source, &aliases)?;
            let destination = Target::parse(&destination, &aliases)?;
            super::copy::mirror(source, destination, remove, dry_run, transfer).await
        }
    }
}

// ---------------------------------------------------------------------------------
// Aliases

async fn alias_command(action: AliasAction, aliases: &mut Aliases) -> Result<(), Error> {
    match action {
        AliasAction::Set(set) => set_alias(set, aliases).await,
        AliasAction::Ls => {
            list_aliases(aliases);
            Ok(())
        }
        AliasAction::Rm { name } => {
            if aliases.remove(&name)? {
                ui::done(
                    format!("Removed {name}"),
                    || json!({"type": "alias", "action": "remove", "name": name}),
                );
                Ok(())
            } else if let Some((_, Origin::Env)) = aliases.get(&name) {
                Err(Error::usage(format!(
                    "{name} comes from {}{}: unset it instead",
                    alias::ENV_PREFIX,
                    name.to_ascii_uppercase()
                )))
            } else {
                Err(Error::new(
                    Kind::NotFound,
                    format!("there's no alias {name}"),
                ))
            }
        }
    }
}

async fn set_alias(set: SetAlias, aliases: &mut Aliases) -> Result<(), Error> {
    let SetAlias {
        name,
        url,
        access_key,
        secret_key_stdin,
        drive,
        region,
        virtual_hosted,
        ca_cert,
        no_check,
    } = set;
    alias::check_name(&name).map_err(Error::usage)?;
    let url = alias::check_url(&url).map_err(Error::usage)?;
    // Checked now, and saved as an absolute path so it works from anywhere.
    let ca_cert = ca_cert
        .map(|path| {
            super::trust::read(&path).map_err(Error::usage)?;
            std::path::absolute(&path).map_err(|e| Error::usage(e.to_string()))
        })
        .transpose()?;
    let (access_key, secret_key) = match drive {
        Some(dir) => drive_keys(&dir)?,
        None => (
            access_key.map_or_else(ask_access_key, Ok)?,
            secret_key(secret_key_stdin)?,
        ),
    };
    let mut alias = Alias {
        url,
        access_key,
        secret_key,
        region,
        path_style: !virtual_hosted,
        session_token: None,
        expires: None,
        ca_cert,
        trust: super::trust::Trust::default(),
    };
    alias.load_trust();
    if !no_check {
        alias.client().list_buckets().send().await.map_err(|e| {
            let err = Error::s3(format!("{} doesn't work with these keys", alias.url), &e);
            let hint = err.hint.clone().map_or_else(
                || "fix it, or save it anyway with --no-check".to_owned(),
                |hint| format!("{hint}; or save it anyway with --no-check"),
            );
            err.with_hint(hint)
        })?;
    }
    let url = alias.url.clone();
    aliases.set(&name, alias)?;
    let path = aliases.path().display().to_string();
    ui::done(
        format!("Added {name} for {url}"),
        || json!({"type": "alias", "action": "set", "name": name, "url": url, "file": path}),
    );
    ui::note(format!("Saved in {path}. Try: teifs ls {name}"));
    if let Some((_, Origin::Env)) = aliases.get(&name) {
        ui::warn(format!(
            "{}{} is set, and wins over the saved alias",
            alias::ENV_PREFIX,
            name.to_ascii_uppercase()
        ));
    }
    Ok(())
}

fn list_aliases(aliases: &Aliases) {
    let mut table = ui::Table::new(&["NAME", "URL", "ACCESS KEY", "EXPIRES", "FROM"]);
    let mut records = Vec::new();
    for (name, alias, origin) in aliases.all() {
        let from = match origin {
            Origin::File => "file".to_owned(),
            Origin::Env => format!("{}{}", alias::ENV_PREFIX, name.to_ascii_uppercase()),
        };
        let expires = match alias.expires_ms() {
            Some(_) if alias.expired() => "expired".to_owned(),
            Some(ms) => crate::units::date(crate::units::from_ms(ms)),
            None if alias.session_token.is_some() => "temporary".to_owned(),
            None => String::new(),
        };
        table.row(vec![
            name.to_owned(),
            alias.url.clone(),
            alias.access_key.clone(),
            expires,
            from.clone(),
        ]);
        records.push(json!({
            "type": "alias",
            "name": name,
            "url": alias.url,
            "accessKey": alias.access_key,
            "region": alias.region,
            "pathStyle": alias.path_style,
            "temporary": alias.session_token.is_some(),
            "expiresMs": alias.expires_ms(),
            "caCert": alias.ca_cert,
            "from": from,
        }));
    }
    ui::rows(
        &table,
        &records,
        "No aliases yet. Add one: teifs alias set NAME URL",
    );
}

/// The keys of the TeiFS drive in `dir`.
fn drive_keys(dir: &Path) -> Result<(String, String), Error> {
    match teifs_server::credentials::load(dir) {
        Ok(Some(credentials)) => Ok((credentials.access_key, credentials.secret_key)),
        Ok(None) => Err(Error::new(
            Kind::NotFound,
            format!(
                "{} has no keys of its own (it's not a drive, or its keys are set with TEIFS_ACCESS_KEY / TEIFS_SECRET_KEY): use --access-key instead",
                dir.display()
            ),
        )),
        Err(e) => Err(Error::general(format!(
            "can't read the keys in {}: {e}",
            teifs_server::credentials::path(dir).display()
        ))),
    }
}

fn ask_access_key() -> Result<String, Error> {
    if !ui::interactive() {
        return Err(Error::usage(
            "give the access key with --access-key or TEIFS_ACCESS_KEY",
        ));
    }
    inquire::Text::new("Access key:")
        .with_validator(|text: &str| {
            Ok(if text.trim().is_empty() {
                inquire::validator::Validation::Invalid("An access key is needed.".into())
            } else {
                inquire::validator::Validation::Valid
            })
        })
        .prompt()
        .map(|key| key.trim().to_owned())
        .map_err(|e| Error::usage(e.to_string()))
}

/// The secret key: from standard input, `TEIFS_SECRET_KEY`, or a hidden prompt.
fn secret_key(from_stdin: bool) -> Result<String, Error> {
    let secret = if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| Error::general(format!("can't read the secret key: {e}")))?;
        line.trim_end_matches(['\n', '\r']).to_owned()
    } else if let Some(secret) = crate::config::env("TEIFS_SECRET_KEY") {
        secret
    } else if ui::interactive() {
        inquire::Password::new("Secret key:")
            .without_confirmation()
            .with_display_mode(inquire::PasswordDisplayMode::Hidden)
            .prompt()
            .map_err(|e| Error::usage(e.to_string()))?
    } else {
        return Err(Error::usage(
            "give the secret key on standard input (--secret-key-stdin) or in TEIFS_SECRET_KEY",
        ));
    };
    if secret.is_empty() {
        return Err(Error::usage("the secret key is empty"));
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------------
// Buckets and listings

async fn list_buckets(client: &Client, alias_name: &str) -> Result<(), Error> {
    let mut token = None;
    loop {
        let page = client
            .list_buckets()
            .max_buckets(1000)
            .set_continuation_token(token)
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't list {alias_name}"), &e))?;
        for bucket in page.buckets() {
            let created = bucket
                .creation_date()
                .and_then(|t| std::time::SystemTime::try_from(*t).ok());
            let name = bucket.name().unwrap_or_default();
            ui::item(
                || {
                    let created = created.map_or_else(|| " ".repeat(19), date);
                    format!("{}  {}", ui::dim(created), ui::folder(format!("{name}/")))
                },
                || json!({"type": "bucket", "name": name, "created": created.map(rfc3339)}),
            );
        }
        token = page.continuation_token().map(str::to_owned);
        if token.is_none() {
            return Ok(());
        }
    }
}

async fn ls(remote: Remote, recursive: bool, versions: bool) -> Result<(), Error> {
    let client = remote.alias.client();
    let Some(bucket) = &remote.bucket else {
        return list_buckets(&client, &remote.alias_name).await;
    };
    let delimiter = (!recursive).then_some("/");
    let what = || format!("can't list {}", remote.display(&remote.key));
    let prefix = if recursive {
        remote.key.clone()
    } else {
        folder_or_prefix(&client, bucket, &remote.key, &remote.display(&remote.key)).await?
    };
    // Names are shown below the folder being listed.
    let shown_from = prefix.rfind('/').map_or(0, |i| i + 1);
    if versions {
        let name = remote.display(&remote.key);
        let any =
            super::versions::ls(&client, bucket, &prefix, delimiter, shown_from, &name).await?;
        return if any || prefix.is_empty() {
            Ok(())
        } else {
            Err(Error::new(Kind::NotFound, format!("nothing at {name}")))
        };
    }
    let mut pages = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(&prefix)
        .set_delimiter(delimiter.map(str::to_owned))
        .into_paginator()
        .send();
    let mut any = false;
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| Error::s3(what(), &e))?;
        // Folders and objects, merged in key order.
        let mut rows: Vec<(&str, Option<&aws_sdk_s3::types::Object>)> = page
            .common_prefixes()
            .iter()
            .filter_map(|p| p.prefix().map(|p| (p, None)))
            .chain(
                page.contents()
                    .iter()
                    .filter_map(|o| o.key().map(|k| (k, Some(o)))),
            )
            .collect();
        rows.sort_by(|a, b| a.0.cmp(b.0));
        any |= !rows.is_empty();
        for (key, object) in rows {
            let name = &key[shown_from..];
            match object {
                None => ui::item(
                    || format!("{:19}  {:>10}  {}", "", ui::dim("DIR"), ui::folder(name)),
                    || json!({"type": "folder", "key": key}),
                ),
                Some(object) => {
                    let modified = object
                        .last_modified()
                        .and_then(|t| std::time::SystemTime::try_from(*t).ok());
                    let bytes = object
                        .size()
                        .and_then(|s| u64::try_from(s).ok())
                        .unwrap_or(0);
                    ui::item(
                        || {
                            let modified = modified.map_or_else(|| " ".repeat(19), date);
                            let size = format!("{:>10}", size(bytes));
                            format!("{}  {}  {name}", ui::dim(modified), ui::dim(size))
                        },
                        || {
                            json!({
                                "type": "object",
                                "key": key,
                                "size": bytes,
                                "modified": modified.map(rfc3339),
                                "etag": object.e_tag(),
                            })
                        },
                    );
                }
            }
        }
    }
    if !any && !prefix.is_empty() {
        return Err(Error::new(
            Kind::NotFound,
            format!("nothing at {}", remote.display(&remote.key)),
        ));
    }
    Ok(())
}

/// What `ls` lists one level of for `key`: `photos/` when `photos` names only a folder
/// (as a folder listing would show what's in it), else `key` as a prefix.
async fn folder_or_prefix(
    client: &Client,
    bucket: &str,
    key: &str,
    name: &str,
) -> Result<String, Error> {
    if key.is_empty() || key.ends_with('/') {
        return Ok(key.to_owned());
    }
    let first = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(key)
        .delimiter("/")
        .max_keys(2)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't list {name}"), &e))?;
    let folder = format!("{key}/");
    let only_folder = first.contents().is_empty()
        && first.common_prefixes().len() == 1
        && first.common_prefixes()[0].prefix() == Some(folder.as_str());
    Ok(if only_folder { folder } else { key.to_owned() })
}

async fn mb(
    remote: Remote,
    layout: Option<crate::LayoutArg>,
    ignore_existing: bool,
    with_lock: bool,
) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let client = remote.alias.client();
    let configuration = (remote.alias.region != alias::DEFAULT_REGION).then(|| {
        CreateBucketConfiguration::builder()
            .location_constraint(BucketLocationConstraint::from(remote.alias.region.as_str()))
            .build()
    });
    let request = client
        .create_bucket()
        .bucket(bucket)
        .set_create_bucket_configuration(configuration)
        .set_object_lock_enabled_for_bucket(with_lock.then_some(true));
    let result = match layout {
        Some(layout) => {
            let value = match layout {
                crate::LayoutArg::Object => "object",
                crate::LayoutArg::Folder => "folder",
            };
            request
                .customize()
                .mutate_request(move |req| {
                    req.headers_mut().insert(teifs_server::LAYOUT_HEADER, value);
                })
                .send()
                .await
        }
        None => request.send().await,
    };
    match result {
        Ok(_) => {
            ui::done(
                format!("Created {name}"),
                || json!({"type": "bucket", "action": "make", "name": name}),
            );
            Ok(())
        }
        Err(e) => {
            let err = Error::s3(format!("can't make {name}"), &e);
            if ignore_existing
                && err.kind == Kind::Conflict
                && client.head_bucket().bucket(bucket).send().await.is_ok()
            {
                ui::done(
                    format!("{name} is already there"),
                    || json!({"type": "bucket", "action": "exists", "name": name}),
                );
                return Ok(());
            }
            Err(err)
        }
    }
}

async fn rb(remote: Remote, force: bool) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    if !remote.key.is_empty() {
        return Err(Error::usage(format!(
            "`rb` removes a whole bucket: give ALIAS/BUCKET, not {}",
            remote.display(&remote.key)
        )));
    }
    let name = remote.display("");
    let client = remote.alias.client();
    if force {
        // Every version and delete marker, which a bucket that had versioning keeps;
        // where versions can't be listed, every object.
        let keys = match listing::versions(&client, bucket, "", None, &name).await {
            Ok((versions, _)) => versions.into_iter().map(|v| (v.key, Some(v.id))).collect(),
            Err(_) => listing::remote(&client, bucket, "", &name)
                .await?
                .into_iter()
                .map(|e| (e.relative, None))
                .collect(),
        };
        delete_keys(&client, bucket, &name, keys, false).await?;
    }
    client
        .delete_bucket()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| {
            let err = Error::s3(format!("can't remove {name}"), &e);
            if err.kind == Kind::Conflict && !force {
                err.with_hint("to delete what's in it too, add --force")
            } else {
                err
            }
        })?;
    ui::done(
        format!("Removed {name}"),
        || json!({"type": "bucket", "action": "remove", "name": name}),
    );
    Ok(())
}

// ---------------------------------------------------------------------------------
// Objects

async fn rm(remote: Remote, recursive: bool, force: bool) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let client = remote.alias.client();
    let name = remote.display(&remote.key);
    if recursive {
        let keys: Vec<(String, Option<String>)> = keys_under(&client, bucket, &remote, &name)
            .await?
            .into_iter()
            .map(|key| (key, None))
            .collect();
        if keys.is_empty() {
            return Err(Error::new(Kind::NotFound, format!("nothing at {name}")));
        }
        let count = keys.len();
        let question = format!("Delete {count} object{} under {name}?", plural(count));
        if !force && !ui::confirm(&question, "add --force to delete without asking")? {
            ui::note("Nothing was deleted.");
            return Ok(());
        }
        delete_keys(&client, bucket, &name, keys, false).await?;
        ui::done(
            format!("Removed {count} object{} under {name}", plural(count)),
            || json!({"type": "remove", "prefix": name, "count": count}),
        );
        return Ok(());
    }
    if remote.key.is_empty() {
        return Err(Error::usage(format!(
            "give a key to remove, like {name}/KEY (or `teifs rb {name}` for the bucket)"
        )));
    }
    let object = object(&remote, &remote.key);
    if let Err(err) = object.head().await {
        return Err(with_folder_hint(err, &client, bucket, &remote, "rm -r --force").await);
    }
    client
        .delete_object()
        .bucket(bucket)
        .key(&remote.key)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't remove {name}"), &e))?;
    ui::done(
        format!("Removed {name}"),
        || json!({"type": "remove", "key": name, "count": 1}),
    );
    Ok(())
}

/// The keys of the objects at `remote`'s key and "in" it (`photos` and `photos/…`, not
/// `photos2`); every key when it names none.
pub(super) async fn keys_under(
    client: &Client,
    bucket: &str,
    remote: &Remote,
    name: &str,
) -> Result<Vec<String>, Error> {
    Ok(listing::remote(client, bucket, &remote.key, name)
        .await?
        .into_iter()
        .filter(|e| {
            remote.key.is_empty()
                || remote.key.ends_with('/')
                || e.relative.is_empty()
                || e.relative.starts_with('/')
        })
        .map(|e| format!("{}{}", remote.key, e.relative))
        .collect())
}

/// Deletes `keys` (each with a version to remove for good, or `None`: the key) in
/// batches, a few at once; `bypass` removes versions a governance retention keeps.
pub(super) async fn delete_keys(
    client: &Client,
    bucket: &str,
    name: &str,
    keys: Vec<(String, Option<String>)>,
    bypass: bool,
) -> Result<(), Error> {
    let batches: Vec<Vec<(String, Option<String>)>> =
        keys.chunks(DELETE_BATCH).map(<[_]>::to_vec).collect();
    stream::iter(batches)
        .map(|batch| async move {
            let objects = batch
                .into_iter()
                .map(|(key, version)| {
                    ObjectIdentifier::builder()
                        .key(key)
                        .set_version_id(version)
                        .build()
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::general(e.to_string()))?;
            let delete = Delete::builder()
                .set_objects(Some(objects))
                .quiet(true)
                .build()
                .map_err(|e| Error::general(e.to_string()))?;
            let out = client
                .delete_objects()
                .bucket(bucket)
                .delete(delete)
                .set_bypass_governance_retention(bypass.then_some(true))
                .send()
                .await
                .map_err(|e| Error::s3(format!("can't delete in {name}"), &e))?;
            match out.errors().first() {
                None => Ok(()),
                Some(first) => Err(Error::general(format!(
                    "can't delete {} object{} in {name}, the first {}: {}",
                    out.errors().len(),
                    plural(out.errors().len()),
                    first.key().unwrap_or_default(),
                    first
                        .message()
                        .or(first.code())
                        .unwrap_or("no reason given")
                ))),
            }
        })
        .buffer_unordered(4)
        .try_collect()
        .await
}

pub(super) async fn cat(remote: Remote, version_id: Option<&str>) -> Result<(), Error> {
    use tokio::io::AsyncWriteExt;
    let bucket = remote.bucket()?;
    let name = remote.display(&remote.key);
    let request = remote
        .alias
        .client()
        .get_object()
        .bucket(bucket)
        .key(&remote.key)
        .set_version_id(version_id.map(str::to_owned))
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled);
    let sse = sse::for_object(&name);
    let got = customer_key!(request, sse.as_deref())
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't read {name}"), &e))?;
    let mut body = got.body;
    let mut stdout = tokio::io::stdout();
    while let Some(chunk) = body
        .try_next()
        .await
        .map_err(|e| Error::new(Kind::Network, format!("can't read {name}: {e}")))?
    {
        match stdout.write_all(&chunk).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(e) => return Err(Error::general(format!("can't write {name} out: {e}"))),
        }
    }
    stdout
        .flush()
        .await
        .map_err(|e| Error::general(format!("can't write {name} out: {e}")))
}

async fn stat(remote: Remote, version_id: Option<&str>) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let client = remote.alias.client();
    if remote.key.is_empty() {
        let name = remote.display("");
        let out = client
            .head_bucket()
            .bucket(bucket)
            .send()
            .await
            .map_err(|e| Error::s3(format!("can't find {name}"), &e))?;
        let region = out
            .bucket_region()
            .unwrap_or(&remote.alias.region)
            .to_owned();
        // A service without versioning just doesn't say.
        let versioning = super::versions::status(&client, bucket).await.ok();
        let lock = super::lock::bucket_lock(&client, bucket).await;
        // Nor does one without default encryption.
        let encryption = super::encrypt::bucket_default(&client, bucket, &name)
            .await
            .ok()
            .flatten()
            .map(|d| d.text());
        let mut fields = vec![("Bucket", name.clone()), ("Region", region.clone())];
        fields.extend(versioning.map(|v| ("Versioning", v.to_owned())));
        fields.extend(lock.clone().map(|l| ("Object Lock", l)));
        fields.extend(encryption.clone().map(|e| ("Encryption", e)));
        ui::details(
            &fields,
            || json!({"type": "bucket", "name": name, "region": region, "versioning": versioning, "objectLock": lock, "encryption": encryption}),
        );
        return Ok(());
    }
    if version_id.is_some() && remote.is_folder() {
        return Err(Error::usage(
            "--version-id names a version of an object: give its key",
        ));
    }
    let name = remote.display(&remote.key);
    let request = client
        .head_object()
        .bucket(bucket)
        .key(&remote.key)
        .set_version_id(version_id.map(str::to_owned))
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled);
    let sse = sse::for_object(&name);
    let out = customer_key!(request, sse.as_deref()).send().await;
    let out = match out {
        Ok(out) => out,
        Err(e) => {
            let err = Error::s3(format!("can't find {name}"), &e);
            return Err(with_folder_hint(err, &client, bucket, &remote, "ls").await);
        }
    };
    show_object(&remote.key, &name, &out);
    Ok(())
}

/// `stat`'s details of an object.
fn show_object(key: &str, name: &str, out: &HeadObjectOutput) {
    let bytes = out
        .content_length()
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0);
    let modified = out
        .last_modified()
        .and_then(|t| std::time::SystemTime::try_from(*t).ok());
    let text = |value: Option<&str>| value.unwrap_or_default().to_owned();
    let storage = out
        .storage_class()
        .map(aws_sdk_s3::types::StorageClass::as_str);
    let encryption = out
        .server_side_encryption()
        .map(aws_sdk_s3::types::ServerSideEncryption::as_str);
    let metadata: BTreeMap<&String, &String> = out
        .metadata()
        .map(|m| m.iter().collect())
        .unwrap_or_default();
    let mut fields = vec![
        ("Name", name.to_owned()),
        ("Size", format!("{} ({bytes} bytes)", size(bytes))),
        (
            "Modified",
            modified
                .map(|t| format!("{} UTC", date(t)))
                .unwrap_or_default(),
        ),
        ("ETag", text(out.e_tag())),
        ("Type", text(out.content_type())),
        ("Encoding", text(out.content_encoding())),
        ("Cache", text(out.cache_control())),
        ("Version", text(out.version_id())),
        ("Storage", text(storage)),
        ("Encryption", text(encryption)),
        ("KMS key", text(out.ssekms_key_id())),
        ("Customer key MD5", text(out.sse_customer_key_md5())),
        (
            "Bucket key",
            text(
                out.bucket_key_enabled()
                    .map(|on| if on { "on" } else { "off" }),
            ),
        ),
        ("CRC32", text(out.checksum_crc32())),
        ("CRC32C", text(out.checksum_crc32_c())),
        ("CRC64NVME", text(out.checksum_crc64_nvme())),
        ("SHA1", text(out.checksum_sha1())),
        ("SHA256", text(out.checksum_sha256())),
    ];
    let retention = out.object_lock_mode().map(|mode| {
        super::lock::retention_text(mode.as_str(), out.object_lock_retain_until_date())
    });
    let legal_hold = out
        .object_lock_legal_hold_status()
        .map(|s| s.as_str().to_ascii_lowercase());
    fields.extend(retention.clone().map(|r| ("Retention", r)));
    fields.extend(legal_hold.clone().map(|h| ("Legal hold", h)));
    fields.extend(
        metadata
            .iter()
            .map(|(k, v)| ("Metadata", format!("{k}: {v}"))),
    );
    ui::details(&fields, || {
        json!({
            "type": "object",
            "key": key,
            "name": name,
            "size": bytes,
            "modified": modified.map(rfc3339),
            "etag": out.e_tag(),
            "contentType": out.content_type(),
            "contentEncoding": out.content_encoding(),
            "cacheControl": out.cache_control(),
            "versionId": out.version_id(),
            "storageClass": storage,
            "encryption": encryption,
            "kmsKeyId": out.ssekms_key_id(),
            "customerKeyMd5": out.sse_customer_key_md5(),
            "bucketKey": out.bucket_key_enabled(),
            "checksums": {
                "crc32": out.checksum_crc32(),
                "crc32c": out.checksum_crc32_c(),
                "crc64nvme": out.checksum_crc64_nvme(),
                "sha1": out.checksum_sha1(),
                "sha256": out.checksum_sha256(),
            },
            "metadata": metadata,
            "retention": out.object_lock_mode().map(|mode| json!({
                "mode": mode.as_str(),
                "retainUntil": out
                    .object_lock_retain_until_date()
                    .and_then(|t| std::time::SystemTime::try_from(*t).ok())
                    .map(rfc3339),
            })),
            "legalHold": legal_hold,
        })
    });
}

async fn presign(
    remote: Remote,
    expires: Duration,
    put: bool,
    max_size: Option<u64>,
) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    if remote.key.is_empty() || remote.key.ends_with('/') {
        return Err(Error::usage(format!(
            "give an object to link to, like {}/KEY",
            remote.display("")
        )));
    }
    if expires > MAX_PRESIGN {
        return Err(Error::usage("a link can work for 7 days at most"));
    }
    let config = PresigningConfig::expires_in(expires).map_err(|e| Error::usage(e.to_string()))?;
    let client = remote.alias.client();
    let name = remote.display(&remote.key);
    let what = || format!("can't make a link for {name}");
    let request = if put {
        // The cap goes into the query before it's signed, so the signature covers it.
        client
            .put_object()
            .bucket(bucket)
            .key(&remote.key)
            .customize()
            .mutate_request(move |req| {
                if let Some(max) = max_size {
                    let uri = req.uri();
                    let sep = if uri.contains('?') { '&' } else { '?' };
                    let capped = format!("{uri}{sep}{MAX_CONTENT_LENGTH}={max}");
                    // A failure here leaves the link without its cap, which is caught below.
                    let _ = req.set_uri(capped);
                }
            })
            .presigned(config)
            .await
            .map_err(|e| Error::s3(what(), &e))?
    } else {
        client
            .get_object()
            .bucket(bucket)
            .key(&remote.key)
            .presigned(config)
            .await
            .map_err(|e| Error::s3(what(), &e))?
    };
    let url = request.uri().to_owned();
    // A link that should be capped and isn't would take any size: never hand one out.
    if let Some(max) = max_size
        && !url.contains(&format!("{MAX_CONTENT_LENGTH}={max}"))
    {
        return Err(Error::general(format!(
            "can't limit the size of a link for {name}"
        )));
    }
    ui::item(
        || url.clone(),
        || json!({"type": "link", "url": url, "method": if put { "PUT" } else { "GET" }, "expiresIn": expires.as_secs(), "maxSize": max_size}),
    );
    Ok(())
}

/// When `err` says an object isn't there but keys under it are, says how to reach them.
pub(super) async fn with_folder_hint(
    err: Error,
    client: &Client,
    bucket: &str,
    remote: &Remote,
    command: &str,
) -> Error {
    if !err.is_not_found() {
        return err;
    }
    let folder = folder_prefix(&remote.key);
    let has_children = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(&folder)
        .max_keys(1)
        .send()
        .await
        .is_ok_and(|out| !out.contents().is_empty());
    if has_children {
        let folder = remote.display(&folder);
        err.with_hint(format!("it's a folder: `teifs {command} {folder}`"))
    } else {
        err
    }
}

pub(super) fn object(remote: &Remote, key: &str) -> Object {
    Object {
        client: remote.alias.client(),
        bucket: remote.bucket.clone().unwrap_or_default(),
        key: key.to_owned(),
        name: remote.display(key),
        endpoint: (remote.alias.url.clone(), remote.alias.access_key.clone()),
        version_id: None,
        sse: super::sse::for_object(&remote.display(key)),
    }
}

pub(super) fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
