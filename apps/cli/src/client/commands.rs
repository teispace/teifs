//! The client commands.

use std::{
    collections::BTreeMap,
    io::{IsTerminal, Write as _},
    path::Path,
    time::Duration,
};

use aws_sdk_s3::{
    Client,
    presigning::PresigningConfig,
    types::{BucketLocationConstraint, CreateBucketConfiguration, Delete, ObjectIdentifier},
};
use futures::{StreamExt, TryStreamExt, stream};

use super::{
    AliasAction, Command, Error, Kind,
    alias::{self, Alias, Aliases, Origin},
    listing,
    target::{Remote, Target, folder_prefix},
    transfer::Object,
};
use crate::units::{date, size};

/// The longest a presigned link can work (Signature V4's limit).
const MAX_PRESIGN: Duration = Duration::from_hours(7 * 24);
/// The most keys one `DeleteObjects` request takes.
const DELETE_BATCH: usize = 1000;

pub async fn run(command: Command) -> Result<(), Error> {
    let mut aliases = Aliases::load()?;
    let remote = |text: &str, what: &str| Target::parse(text, &aliases)?.remote(what);
    match command {
        Command::Alias { action } => alias_command(action, &mut aliases).await,
        Command::Ls { target, recursive } => ls(remote(&target, "ls")?, recursive).await,
        Command::Mb {
            target,
            layout,
            ignore_existing,
        } => mb(remote(&target, "mb")?, layout, ignore_existing).await,
        Command::Rb { target, force } => rb(remote(&target, "rb")?, force).await,
        Command::Cp(args) => super::copy::copy(args, false, &aliases).await,
        Command::Mv(args) => super::copy::copy(args, true, &aliases).await,
        Command::Rm {
            targets,
            recursive,
            force,
        } => {
            if recursive && !force {
                return Err(Error::usage(
                    "`rm --recursive` deletes everything under each prefix: add --force to say you mean it",
                ));
            }
            for target in &targets {
                rm(remote(target, "rm")?, recursive).await?;
            }
            Ok(())
        }
        Command::Cat { targets } => {
            for target in &targets {
                cat(remote(target, "cat")?).await?;
            }
            Ok(())
        }
        Command::Stat { target } => stat(remote(&target, "stat")?).await,
        Command::Presign {
            target,
            expires,
            put,
        } => presign(remote(&target, "presign")?, expires, put).await,
        Command::Mirror {
            source,
            destination,
            remove,
            dry_run,
            transfer,
        } => {
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
        AliasAction::Set {
            name,
            url,
            access_key,
            secret_key_stdin,
            drive,
            region,
            virtual_hosted,
            no_check,
        } => {
            alias::check_name(&name).map_err(Error::usage)?;
            let url = alias::check_url(&url).map_err(Error::usage)?;
            let (access_key, secret_key) = match drive {
                Some(dir) => drive_keys(&dir)?,
                None => (
                    access_key.map_or_else(ask_access_key, Ok)?,
                    secret_key(secret_key_stdin)?,
                ),
            };
            let alias = Alias {
                url,
                access_key,
                secret_key,
                region,
                path_style: !virtual_hosted,
            };
            if !no_check {
                alias.client().list_buckets().send().await.map_err(|e| {
                    let err = Error::s3(format!("{} doesn't work with these keys", alias.url), &e);
                    Error::new(
                        err.kind,
                        format!(
                            "{}\n  Fix it, or save it anyway with --no-check.",
                            err.message
                        ),
                    )
                })?;
            }
            let url = alias.url.clone();
            aliases.set(&name, alias)?;
            println!(
                "Added {name} for {url}; saved in {}",
                aliases.path().display()
            );
            if let Some((_, Origin::Env)) = aliases.get(&name) {
                println!(
                    "Note: {}{} is set, and wins over the saved one.",
                    alias::ENV_PREFIX,
                    name.to_ascii_uppercase()
                );
            }
            Ok(())
        }
        AliasAction::Ls => {
            let all = aliases.all();
            if all.is_empty() {
                println!("No aliases yet. Add one: teifs alias set NAME URL");
            }
            for (name, alias, origin) in all {
                let from = match origin {
                    Origin::File => String::new(),
                    Origin::Env => format!(
                        "  (from {}{})",
                        alias::ENV_PREFIX,
                        name.to_ascii_uppercase()
                    ),
                };
                println!("{name:<12}  {:<32}  {}{from}", alias.url, alias.access_key);
            }
            Ok(())
        }
        AliasAction::Rm { name } => {
            if aliases.remove(&name)? {
                println!("Removed {name}");
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

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn ask_access_key() -> Result<String, Error> {
    if !interactive() {
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
    } else if interactive() {
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

async fn ls(remote: Remote, recursive: bool) -> Result<(), Error> {
    let client = remote.alias.client();
    let Some(bucket) = &remote.bucket else {
        let mut token = None;
        loop {
            let page = client
                .list_buckets()
                .max_buckets(1000)
                .set_continuation_token(token)
                .send()
                .await
                .map_err(|e| Error::s3(format!("can't list {}", remote.alias_name), &e))?;
            for bucket in page.buckets() {
                let created = bucket
                    .creation_date()
                    .and_then(|t| std::time::SystemTime::try_from(*t).ok())
                    .map_or_else(|| " ".repeat(19), date);
                println!("{created}  {}/", bucket.name().unwrap_or_default());
            }
            token = page.continuation_token().map(str::to_owned);
            if token.is_none() {
                return Ok(());
            }
        }
    };
    let mut prefix = remote.key.clone();
    let delimiter = (!recursive).then_some("/");
    let what = || format!("can't list {}", remote.display(&remote.key));
    // `ls home/b/photos` shows what's in photos/, as a folder listing would.
    if !recursive && !prefix.is_empty() && !prefix.ends_with('/') {
        let first = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(&prefix)
            .set_delimiter(delimiter.map(str::to_owned))
            .max_keys(2)
            .send()
            .await
            .map_err(|e| Error::s3(what(), &e))?;
        let folder = format!("{prefix}/");
        if first.contents().is_empty()
            && first.common_prefixes().len() == 1
            && first.common_prefixes()[0].prefix() == Some(folder.as_str())
        {
            prefix = folder;
        }
    }
    // Names are shown below the folder being listed.
    let shown_from = prefix.rfind('/').map_or(0, |i| i + 1);
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
        let mut out = std::io::stdout().lock();
        let mut lines: Vec<(&str, String)> = page
            .common_prefixes()
            .iter()
            .filter_map(|p| p.prefix())
            .map(|p| (p, format!("{:19}  {:>10}  {}", "", "DIR", &p[shown_from..])))
            .chain(page.contents().iter().filter_map(|o| {
                let key = o.key()?;
                let modified = o
                    .last_modified()
                    .and_then(|t| std::time::SystemTime::try_from(*t).ok())
                    .map_or_else(|| " ".repeat(19), date);
                let bytes = o.size().and_then(|s| u64::try_from(s).ok()).unwrap_or(0);
                Some((
                    key,
                    format!("{modified}  {:>10}  {}", size(bytes), &key[shown_from..]),
                ))
            }))
            .collect();
        lines.sort_by(|a, b| a.0.cmp(b.0));
        any |= !lines.is_empty();
        for (_, line) in lines {
            if writeln!(out, "{line}").is_err() {
                // A closed pipe (`| head`): stop quietly.
                return Ok(());
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

async fn mb(
    remote: Remote,
    layout: Option<crate::LayoutArg>,
    ignore_existing: bool,
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
        .set_create_bucket_configuration(configuration);
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
            println!("Made {name}");
            Ok(())
        }
        Err(e) => {
            let err = Error::s3(format!("can't make {name}"), &e);
            if ignore_existing
                && err.kind == Kind::Conflict
                && client.head_bucket().bucket(bucket).send().await.is_ok()
            {
                println!("{name} is already there");
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
        let keys = listing::remote(&client, bucket, "", &name).await?;
        let keys: Vec<String> = keys.into_iter().map(|e| e.relative).collect();
        delete_keys(&client, bucket, &name, keys).await?;
    }
    client
        .delete_bucket()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| {
            let err = Error::s3(format!("can't remove {name}"), &e);
            if err.kind == Kind::Conflict && !force {
                Error::new(
                    err.kind,
                    format!(
                        "{}\n  To delete what's in it too, add --force.",
                        err.message
                    ),
                )
            } else {
                err
            }
        })?;
    println!("Removed {name}");
    Ok(())
}

// ---------------------------------------------------------------------------------
// Objects

async fn rm(remote: Remote, recursive: bool) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let client = remote.alias.client();
    let name = remote.display(&remote.key);
    if recursive {
        // The key itself and what's "in" it (`photos` and `photos/…`, not `photos2`).
        let keys: Vec<String> = listing::remote(&client, bucket, &remote.key, &name)
            .await?
            .into_iter()
            .filter(|e| {
                remote.key.is_empty()
                    || remote.key.ends_with('/')
                    || e.relative.is_empty()
                    || e.relative.starts_with('/')
            })
            .map(|e| format!("{}{}", remote.key, e.relative))
            .collect();
        if keys.is_empty() {
            return Err(Error::new(Kind::NotFound, format!("nothing at {name}")));
        }
        let count = keys.len();
        delete_keys(&client, bucket, &name, keys).await?;
        println!("Removed {count} object{} under {name}", plural(count));
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
    println!("Removed {name}");
    Ok(())
}

/// Deletes `keys` in batches, a few at once.
async fn delete_keys(
    client: &Client,
    bucket: &str,
    name: &str,
    keys: Vec<String>,
) -> Result<(), Error> {
    let batches: Vec<Vec<String>> = keys.chunks(DELETE_BATCH).map(<[String]>::to_vec).collect();
    stream::iter(batches)
        .map(|batch| async move {
            let objects = batch
                .into_iter()
                .map(|key| ObjectIdentifier::builder().key(key).build())
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

async fn cat(remote: Remote) -> Result<(), Error> {
    use tokio::io::AsyncWriteExt;
    let bucket = remote.bucket()?;
    let name = remote.display(&remote.key);
    let got = remote
        .alias
        .client()
        .get_object()
        .bucket(bucket)
        .key(&remote.key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
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

async fn stat(remote: Remote) -> Result<(), Error> {
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
        println!("Bucket:   {name}");
        println!(
            "Region:   {}",
            out.bucket_region().unwrap_or(&remote.alias.region)
        );
        return Ok(());
    }
    let name = remote.display(&remote.key);
    let out = client
        .head_object()
        .bucket(bucket)
        .key(&remote.key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await;
    let out = match out {
        Ok(out) => out,
        Err(e) => {
            let err = Error::s3(format!("can't find {name}"), &e);
            return Err(with_folder_hint(err, &client, bucket, &remote, "ls").await);
        }
    };
    let bytes = out
        .content_length()
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0);
    println!("Name:       {name}");
    println!("Size:       {} ({bytes} bytes)", size(bytes));
    if let Some(modified) = out
        .last_modified()
        .and_then(|t| std::time::SystemTime::try_from(*t).ok())
    {
        println!("Modified:   {} UTC", date(modified));
    }
    let optional = [
        ("ETag", out.e_tag()),
        ("Type", out.content_type()),
        ("Encoding", out.content_encoding()),
        ("Cache", out.cache_control()),
        ("Version", out.version_id()),
        (
            "Storage",
            out.storage_class()
                .map(aws_sdk_s3::types::StorageClass::as_str),
        ),
        (
            "Encryption",
            out.server_side_encryption()
                .map(aws_sdk_s3::types::ServerSideEncryption::as_str),
        ),
        ("KMS key", out.ssekms_key_id()),
        ("CRC32", out.checksum_crc32()),
        ("CRC32C", out.checksum_crc32_c()),
        ("CRC64NVME", out.checksum_crc64_nvme()),
        ("SHA1", out.checksum_sha1()),
        ("SHA256", out.checksum_sha256()),
    ];
    for (label, value) in optional {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            println!("{:<11} {value}", format!("{label}:"));
        }
    }
    if let Some(metadata) = out.metadata().filter(|m| !m.is_empty()) {
        println!("Metadata:");
        for (key, value) in metadata.iter().collect::<BTreeMap<_, _>>() {
            println!("  {key}: {value}");
        }
    }
    Ok(())
}

async fn presign(remote: Remote, expires: Duration, put: bool) -> Result<(), Error> {
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
        client
            .put_object()
            .bucket(bucket)
            .key(&remote.key)
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
    println!("{}", request.uri());
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
        Error::new(
            err.kind,
            format!(
                "{}\n  It's a folder: `teifs {command} {}`",
                err.message,
                remote.display(&folder)
            ),
        )
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
    }
}

pub(super) fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
