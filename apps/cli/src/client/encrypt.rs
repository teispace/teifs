//! Encryption: `teifs encrypt set|clear|info` for how a bucket encrypts new objects and
//! whether it takes customer keys (mc's names), and `teifs encrypt update` to move
//! objects to a KMS key in place (S3's `UpdateObjectEncryption`).

use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,
    types::{
        BlockedEncryptionTypes, EncryptionType, ObjectEncryption, ServerSideEncryption,
        ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule,
        SsekmsEncryption,
    },
};
use serde_json::json;

use super::{
    EncryptAction, Error, SseArg,
    alias::{Alias, Aliases},
    lock::{Change, change_objects},
    target::{Remote, Target},
};
use crate::ui;

/// `teifs encrypt …`.
pub(super) async fn encrypt(action: EncryptAction, aliases: &Aliases) -> Result<(), Error> {
    match action {
        EncryptAction::Set {
            mode,
            args,
            bucket_key,
            block_sse_c,
            allow_sse_c,
        } => {
            let (key, target) = set_args(mode, &args, bucket_key)?;
            let remote = Target::parse(target, aliases)?.remote("encrypt")?;
            let blocked = (block_sse_c || allow_sse_c).then_some(block_sse_c);
            set(&remote, key, bucket_key, blocked).await
        }
        EncryptAction::Clear { target } => {
            let remote = Target::parse(&target, aliases)?.remote("encrypt")?;
            clear(&remote).await
        }
        EncryptAction::Info { target } => {
            let remote = Target::parse(&target, aliases)?.remote("encrypt")?;
            info(&remote).await
        }
        EncryptAction::Update {
            objects,
            kms_key,
            bucket_key,
        } => {
            let remote = Target::parse(&objects.target, aliases)?.remote("encrypt")?;
            let arn = kms_arn(&remote.alias, &kms_key).await?;
            let what = format!("SSE-KMS, key {kms_key}");
            let encryption = ObjectEncryption::Ssekms(
                SsekmsEncryption::builder()
                    .kms_key_arn(arn)
                    .set_bucket_key_enabled(bucket_key.then_some(true))
                    .build()
                    .map_err(|e| Error::usage(e.to_string()))?,
            );
            let change = Change {
                noun: "encryption",
                title: "Encryption",
                record: "encryption",
                what: &what,
            };
            change_objects(
                &remote,
                &objects,
                change,
                move |client, bucket, key, version| {
                    let encryption = encryption.clone();
                    async move {
                        client
                            .update_object_encryption()
                            .bucket(bucket)
                            .key(key)
                            .set_version_id(version)
                            .object_encryption(encryption)
                            .send()
                            .await
                            .map(drop)
                    }
                },
            )
            .await
        }
    }
}

/// `set`'s KMS key (for `sse-kms`) and target, from `[KEY] ALIAS/BUCKET`.
fn set_args(
    mode: SseArg,
    args: &[String],
    bucket_key: bool,
) -> Result<(Option<&str>, &str), Error> {
    match (mode, args) {
        (SseArg::SseKms, [key, target]) => Ok((Some(key), target)),
        (SseArg::SseKms, _) => Err(Error::usage(
            "give the KMS key, then the bucket: sse-kms KEY ALIAS/BUCKET",
        )),
        (SseArg::SseS3, _) if bucket_key => Err(Error::usage(
            "--bucket-key is for SSE-KMS: SSE-S3 keys have no Bucket Key",
        )),
        (SseArg::SseS3, [target]) => Ok((None, target)),
        (SseArg::SseS3, _) => Err(Error::usage("SSE-S3 takes no key: sse-s3 ALIAS/BUCKET")),
    }
}

/// A KMS key's ARN, as `UpdateObjectEncryption` needs it: `key` if it is one, else the
/// key of that name in the alias's region and account.
async fn kms_arn(alias: &Alias, key: &str) -> Result<String, Error> {
    if key.starts_with("arn:") {
        return Ok(key.to_owned());
    }
    let account = crate::sts::account(alias).await?;
    Ok(key_arn(&alias.region, &account, key))
}

fn key_arn(region: &str, account: &str, key: &str) -> String {
    format!("arn:aws:kms:{region}:{account}:key/{key}")
}

/// Sets how the bucket encrypts new objects: with the KMS key `key`, or SSE-S3 without
/// one. `blocked` refuses (`Some(true)`) or allows customer keys; `None` leaves that as
/// it is.
async fn set(
    remote: &Remote,
    key: Option<&str>,
    bucket_key: bool,
    blocked: Option<bool>,
) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let algorithm = if key.is_some() {
        ServerSideEncryption::AwsKms
    } else {
        ServerSideEncryption::Aes256
    };
    let by_default = ServerSideEncryptionByDefault::builder()
        .sse_algorithm(algorithm.clone())
        .set_kms_master_key_id(key.map(str::to_owned))
        .build()
        .map_err(|e| Error::usage(e.to_string()))?;
    let blocked_types = blocked.map(|on| {
        BlockedEncryptionTypes::builder()
            .encryption_type(if on {
                EncryptionType::SseC
            } else {
                EncryptionType::None
            })
            .build()
    });
    let rule = ServerSideEncryptionRule::builder()
        .apply_server_side_encryption_by_default(by_default)
        .set_bucket_key_enabled(key.map(|_| bucket_key))
        .set_blocked_encryption_types(blocked_types)
        .build();
    let config = ServerSideEncryptionConfiguration::builder()
        .rules(rule)
        .build()
        .map_err(|e| Error::usage(e.to_string()))?;
    remote
        .alias
        .client()
        .put_bucket_encryption()
        .bucket(bucket)
        .server_side_encryption_configuration(config)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't set the encryption of {name}"), &e))?;
    let set = BucketDefault {
        algorithm: algorithm.as_str().to_owned(),
        kms_key: key.map(str::to_owned),
        bucket_key,
        sse_c_blocked: blocked,
    };
    ui::done(format!("Encryption of {name}: {}", set.text()), || {
        set.record(&name)
    });
    Ok(())
}

async fn clear(remote: &Remote) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    remote
        .alias
        .client()
        .delete_bucket_encryption()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't clear the encryption of {name}"), &e))?;
    ui::done(
        format!("Encryption of {name}: SSE-S3, the default"),
        || json!({"type": "encryption", "bucket": name, "algorithm": "AES256"}),
    );
    Ok(())
}

async fn info(remote: &Remote) -> Result<(), Error> {
    let bucket = remote.bucket()?;
    let name = remote.display("");
    let client = remote.alias.client();
    let found = bucket_default(&client, bucket, &name).await?;
    let mut fields = vec![("Bucket", name.clone())];
    match &found {
        None => fields.push(("Encryption", "none".to_owned())),
        Some(found) => {
            fields.push((
                "Encryption",
                mode_text(&found.algorithm, found.kms_key.as_deref()),
            ));
            if found.algorithm != ServerSideEncryption::Aes256.as_str() {
                fields.push(("Bucket key", on_off(found.bucket_key).to_owned()));
            }
            fields.extend(
                found
                    .sse_c_blocked
                    .map(|b| ("SSE-C", if b { "blocked" } else { "allowed" }.to_owned())),
            );
        }
    }
    ui::details(&fields, || match &found {
        None => json!({"type": "encryption", "bucket": name, "algorithm": null}),
        Some(found) => found.record(&name),
    });
    Ok(())
}

/// How a bucket encrypts new objects, as `GetBucketEncryption` says.
pub(super) struct BucketDefault {
    /// `AES256`, `aws:kms` or `aws:kms:dsse`.
    algorithm: String,
    kms_key: Option<String>,
    bucket_key: bool,
    /// Whether customer keys are refused; `None` when the server doesn't say.
    sse_c_blocked: Option<bool>,
}

impl BucketDefault {
    /// As words: `SSE-KMS, key photos, bucket key on, SSE-C blocked`.
    pub(super) fn text(&self) -> String {
        let mut text = mode_text(&self.algorithm, self.kms_key.as_deref());
        if self.bucket_key {
            text.push_str(", bucket key on");
        }
        if let Some(blocked) = self.sse_c_blocked {
            text.push_str(if blocked {
                ", SSE-C blocked"
            } else {
                ", SSE-C allowed"
            });
        }
        text
    }

    fn record(&self, bucket: &str) -> serde_json::Value {
        json!({
            "type": "encryption",
            "bucket": bucket,
            "algorithm": self.algorithm,
            "kmsKeyId": self.kms_key,
            "bucketKey": self.bucket_key,
            "sseCBlocked": self.sse_c_blocked,
        })
    }
}

/// The bucket's default encryption; `None` if it has none.
pub(super) async fn bucket_default(
    client: &Client,
    bucket: &str,
    name: &str,
) -> Result<Option<BucketDefault>, Error> {
    let out = match client.get_bucket_encryption().bucket(bucket).send().await {
        Ok(out) => out,
        Err(e)
            if e.as_service_error().and_then(ProvideErrorMetadata::code)
                == Some("ServerSideEncryptionConfigurationNotFoundError") =>
        {
            return Ok(None);
        }
        Err(e) => {
            return Err(Error::s3(
                format!("can't read the encryption of {name}"),
                &e,
            ));
        }
    };
    let rule = out
        .server_side_encryption_configuration()
        .and_then(|c| c.rules().first());
    let Some(by_default) =
        rule.and_then(ServerSideEncryptionRule::apply_server_side_encryption_by_default)
    else {
        return Ok(None);
    };
    let sse_c_blocked = rule
        .and_then(ServerSideEncryptionRule::blocked_encryption_types)
        .map(|b| b.encryption_type().contains(&EncryptionType::SseC));
    Ok(Some(BucketDefault {
        algorithm: by_default.sse_algorithm().as_str().to_owned(),
        kms_key: by_default.kms_master_key_id().map(str::to_owned),
        bucket_key: rule.and_then(ServerSideEncryptionRule::bucket_key_enabled) == Some(true),
        sse_c_blocked,
    }))
}

/// An algorithm and key as words: `SSE-S3`, or `SSE-KMS, key photos`.
fn mode_text(algorithm: &str, key: Option<&str>) -> String {
    let mode = match algorithm {
        "AES256" => "SSE-S3",
        "aws:kms" => "SSE-KMS",
        "aws:kms:dsse" => "DSSE-KMS",
        other => other,
    };
    key.map_or_else(|| mode.to_owned(), |key| format!("{mode}, key {key}"))
}

const fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|&a| a.to_owned()).collect()
    }

    #[test]
    fn set_takes_a_key_for_kms_only() {
        let kms = strings(&["photos", "t/b"]);
        let one = strings(&["t/b"]);
        assert_eq!(
            set_args(SseArg::SseKms, &kms, true).unwrap(),
            (Some("photos"), "t/b")
        );
        assert_eq!(set_args(SseArg::SseS3, &one, false).unwrap(), (None, "t/b"));
        assert!(set_args(SseArg::SseKms, &one, false).is_err());
        assert!(set_args(SseArg::SseS3, &kms, false).is_err());
        assert!(set_args(SseArg::SseS3, &one, true).is_err());
    }

    #[test]
    fn defaults_read_as_words() {
        assert_eq!(
            key_arn("eu-west-1", "123456789012", "a"),
            "arn:aws:kms:eu-west-1:123456789012:key/a"
        );
        assert_eq!(mode_text("AES256", None), "SSE-S3");
        assert_eq!(mode_text("aws:kms:dsse", Some("k")), "DSSE-KMS, key k");
        let set = BucketDefault {
            algorithm: "aws:kms".to_owned(),
            kms_key: Some("photos".to_owned()),
            bucket_key: true,
            sse_c_blocked: Some(true),
        };
        assert_eq!(
            set.text(),
            "SSE-KMS, key photos, bucket key on, SSE-C blocked"
        );
        let plain = BucketDefault {
            algorithm: "AES256".to_owned(),
            kms_key: None,
            bucket_key: false,
            sse_c_blocked: Some(false),
        };
        assert_eq!(plain.text(), "SSE-S3, SSE-C allowed");
        assert_eq!(plain.record("t/b")["sseCBlocked"], false);
    }
}
