//! `MinIO`'s bucket metadata export and import (`mc admin cluster bucket export|import`):
//! a zip of `<bucket>/<file>`, each file a setting as S3's calls take it (`policy.json`,
//! `lifecycle.xml`, `tagging.xml`…), so buckets' settings move between TeiFS and `MinIO`.
//!
//! An import goes through TeiFS's own ([`bucket_export::apply`]): a bucket that isn't
//! there is made, and each setting is checked as S3's call checks it.

use std::{collections::BTreeMap, io::Read as _};

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use s3s::{
    Body, S3Error, S3Request, S3Response, S3Result, dto,
    xml::{Deserialize, Deserializer, Serialize, Serializer},
};
use serde_json::{Map, Value};
use teifs_store::{BucketEncryption, BucketSettings, Store, Versioning};
use teifs_types::admin::{BucketImportItem, ExportedBucket};

use crate::{
    admin, bucket_export, cors,
    errors::StoreResultExt,
    lifecycle,
    minio_profile::archive,
    notification, object_lock, quota,
    routes::{Routes, s3_refusal, signed_body},
    sse, tagging,
};

const POLICY: &str = "policy.json";
const NOTIFICATION: &str = "notification.xml";
const LIFECYCLE: &str = "lifecycle.xml";
const ENCRYPTION: &str = "bucket-encryption.xml";
const TAGGING: &str = "tagging.xml";
const QUOTA: &str = "quota.json";
const OBJECT_LOCK: &str = "object-lock.xml";
const VERSIONING: &str = "versioning.xml";
/// Not in `MinIO`'s export, which leaves CORS out; its import passes over it.
const CORS: &str = "cors.xml";

/// The largest file of an import read.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `GET export-bucket-metadata[?bucket=NAME]`.
    Export,
    /// `PUT import-bucket-metadata`.
    Import,
}

impl Call {
    /// The call's name, in metrics and the audit log (`MinIO`'s).
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Export => "ExportBucketMetadata",
            Self::Import => "ImportBucketMetadata",
        }
    }

    pub(crate) async fn call(
        self,
        routes: &Routes,
        mut req: S3Request<Body>,
    ) -> S3Result<S3Response<Body>> {
        if self == Self::Export {
            let only = admin::only_bucket(req.uri.query())?;
            let files = export(&routes.store, only.as_deref()).await?;
            let zip = archive(files.into_iter()).map_err(|err| {
                tracing::error!(error = %err, "the bucket export couldn't be zipped");
                admin::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "The bucket export couldn't be zipped.",
                )
            })?;
            let mut response = S3Response::new(Body::from(Bytes::from(zip)));
            response.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            );
            return Ok(response);
        }
        let body = signed_body(&mut req, admin::MAX_IMPORT_BYTES)
            .await
            .map_err(s3_refusal)?;
        let notifier = routes.events.notifier();
        let mut report = Report::default();
        let buckets = read(&body, &routes.store, notifier, &mut report).await?;
        let applied = bucket_export::apply(
            &routes.store,
            &routes.rules,
            notifier,
            (
                &routes.iam.account(),
                (&routes.access_log, &routes.request_metrics),
            ),
            &buckets,
        )
        .await;
        for item in applied.items {
            report.applied(&item);
        }
        Ok(admin::json(&report))
    }
}

/// Each bucket's settings as `MinIO`'s files.
async fn export(store: &Store, only: Option<&str>) -> S3Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    let mut found = false;
    for info in store.list_buckets().await.s3()? {
        if only.is_some_and(|only| only != info.name) {
            continue;
        }
        found = true;
        let settings = store.bucket_settings(&info.name).await.s3()?;
        let versioning = store.bucket_versioning(&info.name).await.s3()?;
        for (name, bytes) in bucket_files(&settings, versioning)? {
            files.push((format!("{}/{name}", info.name), bytes));
        }
    }
    if let Some(only) = only
        && !found
    {
        return Err(bucket_export::no_such_bucket(only));
    }
    Ok(files)
}

fn xml(value: &impl Serialize) -> S3Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Serializer::new(&mut bytes))
        .map_err(S3Error::internal_error)?;
    Ok(bytes)
}

/// A bucket's files, in `MinIO`'s order.
fn bucket_files(
    settings: &BucketSettings,
    versioning: Versioning,
) -> S3Result<Vec<(&'static str, Vec<u8>)>> {
    let mut files = Vec::new();
    if let Some(policy) = &settings.policy {
        files.push((POLICY, policy.clone().into_bytes()));
    }
    if let Some(config) = &settings.notifications {
        files.push((NOTIFICATION, xml(&notification::to_dto(Some(config)))?));
    }
    if let Some(config) = &settings.lifecycle {
        let rules = lifecycle::to_dto(config).rules.unwrap_or_default();
        let config = dto::BucketLifecycleConfiguration { rules };
        files.push((LIFECYCLE, xml(&config)?));
    }
    if let Some(config) = &settings.encryption {
        files.push((ENCRYPTION, xml(&sse::bucket_encryption_to_dto(config))?));
    }
    if let Some(tags) = &settings.tags {
        let tagging = dto::Tagging {
            tag_set: tagging::to_dto(tags),
        };
        files.push((TAGGING, xml(&tagging)?));
    }
    if let Some(bytes) = settings.quota {
        files.push((QUOTA, quota::to_json(Some(bytes))));
    }
    if let Some(lock) = &settings.object_lock {
        files.push((OBJECT_LOCK, xml(&object_lock::config_to_dto(lock))?));
    }
    let status = match versioning {
        Versioning::Unversioned => None,
        Versioning::Enabled => Some(dto::BucketVersioningStatus::ENABLED),
        Versioning::Suspended => Some(dto::BucketVersioningStatus::SUSPENDED),
    };
    if let Some(status) = status {
        let config = dto::VersioningConfiguration {
            status: Some(dto::BucketVersioningStatus::from_static(status)),
            ..Default::default()
        };
        files.push((VERSIONING, xml(&config)?));
    }
    if let Some(rules) = &settings.cors {
        let config = dto::CORSConfiguration {
            cors_rules: cors::to_dto(rules.clone()),
        };
        files.push((CORS, xml(&config)?));
    }
    Ok(files)
}

fn parse_xml<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> S3Result<T> {
    let mut d = Deserializer::new(bytes);
    T::deserialize(&mut d)
        .and_then(|value| d.expect_eof().map(|()| value))
        .map_err(|e| s3s::s3_error!(MalformedXML, "The XML isn't well-formed: {e}"))
}

/// The buckets a zip gives, as TeiFS's import takes them; what can't be read is
/// reported as `MinIO` reports it.
async fn read(
    zip: &[u8],
    store: &Store,
    notifier: &teifs_notify::Notifier,
    report: &mut Report,
) -> S3Result<Vec<ExportedBucket>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).map_err(|_| {
        admin::error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Invalid Request (invalid argument)",
        )
    })?;
    let mut buckets: BTreeMap<String, ExportedBucket> = BTreeMap::new();
    for index in 0..archive.len() {
        let (path, bytes) = {
            let entry = match archive.by_index(index) {
                Ok(entry) => entry,
                Err(e) => {
                    report.set(&format!("#{index}"), "", e.to_string());
                    continue;
                }
            };
            let path = entry.name().to_owned();
            let mut bytes = Vec::new();
            if let Err(e) = entry.take(MAX_FILE_BYTES).read_to_end(&mut bytes) {
                report.set(&path, "", e.to_string());
                continue;
            }
            (path, bytes)
        };
        let Some((bucket, file)) = path.split_once('/').filter(|(_, f)| !f.contains('/')) else {
            let err = "malformed zip - expecting format bucket/<config.json>";
            report.set(&path, "", err.to_owned());
            continue;
        };
        let entry = buckets
            .entry(bucket.to_owned())
            .or_insert_with(|| ExportedBucket {
                name: bucket.to_owned(),
                layout: String::new(),
                versioning: String::new(),
                settings: Map::new(),
            });
        match setting(file, &bytes, store, bucket, notifier).await {
            Ok(None) => {}
            Ok(Some(("versioning", value))) => {
                value
                    .as_str()
                    .unwrap_or_default()
                    .clone_into(&mut entry.versioning);
            }
            Ok(Some((name, value))) => {
                entry.settings.insert(name.to_owned(), value);
            }
            Err(err) => report.set(bucket, file, message(&err)),
        }
    }
    // Object Lock needs versioning: `MinIO` makes such a bucket with both.
    for bucket in buckets.values_mut() {
        if bucket.settings.contains_key("objectLock") && bucket.versioning.is_empty() {
            "enabled".clone_into(&mut bucket.versioning);
        }
    }
    Ok(buckets.into_values().collect())
}

/// A file's setting, by its name in TeiFS's import (versioning's apart), checked as S3's
/// call checks it: `None` for a file `MinIO`'s import
/// passes over (replication and its targets, which need credentials it doesn't carry).
async fn setting(
    file: &str,
    bytes: &[u8],
    store: &Store,
    bucket: &str,
    notifier: &teifs_notify::Notifier,
) -> S3Result<Option<(&'static str, Value)>> {
    let (setting, value) = match file {
        POLICY => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| s3s::s3_error!(MalformedPolicy, "The policy isn't text"))?;
            ("policy", Value::from(text))
        }
        NOTIFICATION => {
            let config: dto::NotificationConfiguration = parse_xml(bytes)?;
            let bus = notifier.event_bridge().is_some();
            let config = notification::from_dto(config, |arn| notifier.resolve(arn), bus)?;
            ("notifications", json(&config)?)
        }
        LIFECYCLE => {
            let config: dto::BucketLifecycleConfiguration = parse_xml(bytes)?;
            (
                "lifecycle",
                json(&lifecycle::from_dto(Some(config), None)?)?,
            )
        }
        ENCRYPTION => {
            let config: dto::ServerSideEncryptionConfiguration = parse_xml(bytes)?;
            let current = match store.bucket_encryption(bucket).await {
                Ok(Some(current)) => current,
                _ => BucketEncryption::aws_default(),
            };
            let config = sse::bucket_encryption_from_dto(&config, &current)?;
            ("encryption", json(&config)?)
        }
        TAGGING => {
            let tagging: dto::Tagging = parse_xml(bytes)?;
            let tags: BTreeMap<String, String> = tagging::from_dto(tagging).into_iter().collect();
            ("tags", json(&tags)?)
        }
        QUOTA => {
            let Some(bytes) = quota::read(&Bytes::copy_from_slice(bytes))? else {
                return Ok(None);
            };
            ("quota", Value::from(bytes))
        }
        OBJECT_LOCK => {
            let config: dto::ObjectLockConfiguration = parse_xml(bytes)?;
            (
                "objectLock",
                json(&object_lock::config_from_dto(Some(config))?)?,
            )
        }
        VERSIONING => {
            let config: dto::VersioningConfiguration = parse_xml(bytes)?;
            let name = match config
                .status
                .as_ref()
                .map(dto::BucketVersioningStatus::as_str)
            {
                Some(dto::BucketVersioningStatus::ENABLED) => "enabled",
                Some(dto::BucketVersioningStatus::SUSPENDED) => "suspended",
                _ => {
                    return Err(s3s::s3_error!(
                        MalformedXML,
                        "The versioning status isn't Enabled or Suspended"
                    ));
                }
            };
            ("versioning", Value::from(name))
        }
        CORS => {
            let config: dto::CORSConfiguration = parse_xml(bytes)?;
            ("cors", json(&cors::from_dto(config)?)?)
        }
        _ => return Ok(None),
    };
    Ok(Some((setting, value)))
}

fn json(value: &impl serde::Serialize) -> S3Result<Value> {
    serde_json::to_value(value).map_err(S3Error::internal_error)
}

/// What an item's failure says.
fn message(err: &S3Error) -> String {
    err.message()
        .map_or_else(|| err.code().as_str().to_owned(), str::to_owned)
}

/// madmin's `BucketMetaImportErrs`.
#[derive(Debug, Default, serde::Serialize)]
struct Report {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    buckets: BTreeMap<String, BucketStatus>,
}

/// madmin's `BucketStatus`.
#[derive(Debug, Default, serde::Serialize)]
struct BucketStatus {
    olock: MetaStatus,
    versioning: MetaStatus,
    policy: MetaStatus,
    tagging: MetaStatus,
    sse: MetaStatus,
    lifecycle: MetaStatus,
    notification: MetaStatus,
    quota: MetaStatus,
    cors: MetaStatus,
    qos: MetaStatus,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

/// madmin's `MetaStatus`.
#[derive(Debug, Default, serde::Serialize)]
struct MetaStatus {
    #[serde(rename = "isSet")]
    is_set: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

impl Report {
    /// Records a `MinIO` file's outcome; a file of no setting is the bucket's error.
    fn set(&mut self, bucket: &str, file: &str, error: String) {
        let status = self.buckets.entry(bucket.to_owned()).or_default();
        let meta = match file {
            OBJECT_LOCK => &mut status.olock,
            VERSIONING => &mut status.versioning,
            POLICY => &mut status.policy,
            TAGGING => &mut status.tagging,
            ENCRYPTION => &mut status.sse,
            LIFECYCLE => &mut status.lifecycle,
            NOTIFICATION => &mut status.notification,
            QUOTA => &mut status.quota,
            CORS => &mut status.cors,
            _ => {
                status.error = error;
                return;
            }
        };
        *meta = MetaStatus {
            is_set: true,
            error,
        };
    }

    /// Records an item TeiFS's import reports, by the file that gave it.
    fn applied(&mut self, item: &BucketImportItem) {
        let file = match item.item.as_str() {
            "objectLock" => OBJECT_LOCK,
            "versioning" => VERSIONING,
            "policy" => POLICY,
            "tags" => TAGGING,
            "encryption" => ENCRYPTION,
            "lifecycle" => LIFECYCLE,
            "notifications" => NOTIFICATION,
            "quota" => QUOTA,
            "cors" => CORS,
            // The bucket made: a failure is the bucket's.
            _ if item.error.is_none() => return,
            _ => "",
        };
        self.set(&item.bucket, file, item.error.clone().unwrap_or_default());
    }
}
