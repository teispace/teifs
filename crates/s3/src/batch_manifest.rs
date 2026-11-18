//! The S3 Batch Operations manifests that aren't one CSV file: an S3 Inventory report
//! (`S3InventoryReport_CSV_20161130`: a `manifest.json` that names gzipped CSV data
//! files, its `fileSchema` saying what each column is), and a list the job makes itself
//! of a bucket's objects (`ManifestGenerator`), with the filter it's given, written as
//! a manifest of the same kind (`S3InventoryReport_CSV_20211130`) when asked.
//!
//! A job reads such files from where it got to: which file, and how many of its lines
//! it ran (gzipped files are read from their start, so the file being read is kept
//! open between pages). A list the job keeps to itself goes on from the last object it
//! ran, in key order, and takes only objects written before the job listed them.

use std::{
    io::{BufRead, BufReader, Cursor},
    sync::{Arc, Mutex},
};

use aws_sdk_s3::{
    Client,
    primitives::ByteStream,
    types::{ServerSideEncryption, StorageClass},
};
use bytes::Bytes;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use teifs_store::{After, ListQuery, Store, VersionsQuery};
use teifs_types::{
    ObjectInfo, SseMode,
    batch::{
        BatchJob, EncryptionFilter, GeneratedManifest, GeneratorFilter, Manifest, ManifestField,
        ManifestFile, ManifestGenerator, ManifestOutput, Operation, OperationJob,
    },
    replication::ReplicationConfig,
};

use crate::{
    access,
    batch_operations::{AsRole, Stop, Task, stop, task},
    control_jobs::{Empty, Members, bad_request, iso, members, millis_of},
};

/// An inventory report's manifest format.
pub(crate) const INVENTORY_FORMAT: &str = "S3InventoryReport_CSV_20161130";

/// The format of the manifest a job writes of the objects it listed.
pub(crate) const GENERATED_FORMAT: &str = "S3InventoryReport_CSV_20211130";

/// The columns of a generated manifest's data files.
const GENERATED_SCHEMA: &str = "Bucket, Key, VersionId";

/// The most lines a generated data file holds.
const LINES_PER_FILE: u64 = 1_000_000;

/// How many objects a listing page holds.
const LIST_PAGE: usize = 1000;

/// The storage classes a filter may name.
const STORAGE_CLASSES: [&str; 7] = [
    "STANDARD",
    "STANDARD_IA",
    "ONEZONE_IA",
    "GLACIER",
    "INTELLIGENT_TIERING",
    "DEEP_ARCHIVE",
    "GLACIER_IR",
];

/// The replication statuses a filter may name.
const REPLICATION_STATUSES: [&str; 4] = ["COMPLETED", "FAILED", "REPLICA", "NONE"];

// ---- Reading a job's request -------------------------------------------------------

/// `ManifestGenerator`, as S3 Control writes it.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct GeneratorXml {
    #[serde(
        rename = "S3JobManifestGenerator",
        skip_serializing_if = "Option::is_none"
    )]
    s3: Option<S3GeneratorXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct S3GeneratorXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_bucket_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_output_location: Option<OutputXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<FilterXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enable_manifest_output: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OutputXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_manifest_bucket_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_encryption: Option<OutputEncryptionXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_format: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OutputEncryptionXml {
    #[serde(rename = "SSE-S3", skip_serializing_if = "Option::is_none")]
    sse_s3: Option<Empty>,
    #[serde(rename = "SSE-KMS", skip_serializing_if = "Option::is_none")]
    sse_kms: Option<KeyIdXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeyIdXml {
    #[serde(default)]
    key_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FilterXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    eligible_for_replication: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_replication_statuses: Option<Members<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_name_constraint: Option<KeyNameXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_size_greater_than_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_size_less_than_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_any_storage_class: Option<Members<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_any_object_encryption: Option<EncryptionsXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyNameXml {
    #[serde(rename = "MatchAnyPrefix", skip_serializing_if = "Option::is_none")]
    prefixes: Option<Members<String>>,
    #[serde(rename = "MatchAnySuffix", skip_serializing_if = "Option::is_none")]
    suffixes: Option<Members<String>>,
    #[serde(rename = "MatchAnySubstring", skip_serializing_if = "Option::is_none")]
    substrings: Option<Members<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EncryptionsXml {
    #[serde(rename = "ObjectEncryption", default)]
    items: Vec<EncryptionFilterXml>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EncryptionFilterXml {
    #[serde(rename = "SSE-S3", skip_serializing_if = "Option::is_none")]
    sse_s3: Option<Empty>,
    #[serde(rename = "SSE-KMS", skip_serializing_if = "Option::is_none")]
    sse_kms: Option<KmsFilterXml>,
    #[serde(rename = "DSSE-KMS", skip_serializing_if = "Option::is_none")]
    dsse_kms: Option<KmsFilterXml>,
    #[serde(rename = "SSE-C", skip_serializing_if = "Option::is_none")]
    sse_c: Option<Empty>,
    #[serde(rename = "NOT-SSE", skip_serializing_if = "Option::is_none")]
    not_sse: Option<Empty>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KmsFilterXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    kms_key_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_key_enabled: Option<bool>,
}

/// `GeneratedManifestDescriptor`, as `DescribeJob` answers it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct DescriptorXml {
    format: &'static str,
    location: DescriptorLocationXml,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DescriptorLocationXml {
    object_arn: String,
    #[serde(rename = "ETag")]
    etag: String,
}

/// The bucket of a bucket's ARN (`arn:aws:s3:::bucket`).
fn bucket_of(arn: &str) -> Option<String> {
    let bucket = arn.strip_prefix("arn:")?.split_once(":s3:::")?.1;
    (!bucket.is_empty() && !bucket.contains('/') && arn.len() <= 128).then(|| bucket.to_owned())
}

/// Whether `owner` is an account id (12 digits).
fn is_account(owner: &str) -> bool {
    owner.len() == 12 && owner.bytes().all(|b| b.is_ascii_digit())
}

fn account(owner: Option<String>, name: &str) -> s3s::S3Result<Option<String>> {
    match owner {
        Some(owner) if !is_account(&owner) => Err(bad_request(format!(
            "{name} must be an account id of 12 digits."
        ))),
        owner => Ok(owner),
    }
}

/// A job's `ManifestGenerator`.
pub(crate) fn generator_of(given: GeneratorXml) -> s3s::S3Result<ManifestGenerator> {
    let given = given
        .s3
        .ok_or_else(|| bad_request("A ManifestGenerator needs an S3JobManifestGenerator."))?;
    let source_bucket = given
        .source_bucket
        .as_deref()
        .and_then(bucket_of)
        .ok_or_else(|| bad_request("The generator's SourceBucket must be a bucket's ARN."))?;
    let output_enabled = given
        .enable_manifest_output
        .ok_or_else(|| bad_request("The generator needs EnableManifestOutput."))?;
    let output = given.manifest_output_location.map(output_of).transpose()?;
    if output_enabled && output.is_none() {
        return Err(bad_request(
            "A generator that writes its manifest needs a ManifestOutputLocation.",
        ));
    }
    Ok(ManifestGenerator {
        source_bucket,
        expected_bucket_owner: account(given.expected_bucket_owner, "ExpectedBucketOwner")?,
        filter: given.filter.map(filter_of).transpose()?.unwrap_or_default(),
        output_enabled,
        output,
    })
}

fn output_of(given: OutputXml) -> s3s::S3Result<ManifestOutput> {
    let bucket = given.bucket.as_deref().and_then(bucket_of).ok_or_else(|| {
        bad_request("The ManifestOutputLocation's Bucket must be a bucket's ARN.")
    })?;
    if given.manifest_format.as_deref() != Some(GENERATED_FORMAT) {
        return Err(bad_request(format!(
            "A generated manifest's ManifestFormat is {GENERATED_FORMAT}."
        )));
    }
    if given
        .manifest_prefix
        .as_ref()
        .is_some_and(|p| !(1..=512).contains(&p.len()))
    {
        return Err(bad_request("ManifestPrefix is 1 to 512 characters."));
    }
    let (sse_s3, kms_key) = match given.manifest_encryption {
        None => (false, None),
        Some(OutputEncryptionXml {
            sse_s3: Some(_),
            sse_kms: None,
        }) => (true, None),
        Some(OutputEncryptionXml {
            sse_s3: None,
            sse_kms: Some(kms),
        }) if !kms.key_id.is_empty() => (false, Some(kms.key_id)),
        Some(_) => {
            return Err(bad_request(
                "ManifestEncryption is SSE-S3, or SSE-KMS with its KeyId.",
            ));
        }
    };
    Ok(ManifestOutput {
        bucket,
        prefix: given.manifest_prefix,
        expected_owner: account(
            given.expected_manifest_bucket_owner,
            "ExpectedManifestBucketOwner",
        )?,
        kms_key,
        sse_s3,
    })
}

/// The one value a `MatchAny…` list of a key name constraint holds.
fn one_name(given: Option<Members<String>>, name: &str) -> s3s::S3Result<Vec<String>> {
    match given {
        None => Ok(Vec::new()),
        Some(list) if list.member.len() == 1 && (1..=1024).contains(&list.member[0].len()) => {
            Ok(list.member)
        }
        Some(_) => Err(bad_request(format!(
            "{name} holds one value of 1 to 1024 characters."
        ))),
    }
}

/// The values of a list, each one of `allowed`.
fn listed(
    given: Option<Members<String>>,
    allowed: &[&str],
    name: &str,
) -> s3s::S3Result<Vec<String>> {
    let values = given.map(|list| list.member).unwrap_or_default();
    match values.iter().find(|v| !allowed.contains(&v.as_str())) {
        Some(wrong) => Err(bad_request(format!(
            "{wrong} isn't one of {name}'s values: {}.",
            allowed.join(", ")
        ))),
        None => Ok(values),
    }
}

fn size(given: Option<i64>, name: &str) -> s3s::S3Result<Option<u64>> {
    given
        .map(|n| u64::try_from(n).map_err(|_| bad_request(format!("{name} can't be negative."))))
        .transpose()
}

fn filter_of(given: FilterXml) -> s3s::S3Result<GeneratorFilter> {
    let names = given.key_name_constraint.unwrap_or_default();
    let encryption = match given.match_any_object_encryption {
        None => None,
        Some(EncryptionsXml { items }) if items.len() == 1 => {
            items.into_iter().next().map(encryption_of).transpose()?
        }
        Some(_) => {
            return Err(bad_request(
                "MatchAnyObjectEncryption holds one ObjectEncryption.",
            ));
        }
    };
    Ok(GeneratorFilter {
        created_after_ms: given
            .created_after
            .map(|date| millis_of(&date, "CreatedAfter"))
            .transpose()?,
        created_before_ms: given
            .created_before
            .map(|date| millis_of(&date, "CreatedBefore"))
            .transpose()?,
        eligible_for_replication: given.eligible_for_replication,
        prefixes: one_name(names.prefixes, "MatchAnyPrefix")?,
        substrings: one_name(names.substrings, "MatchAnySubstring")?,
        suffixes: one_name(names.suffixes, "MatchAnySuffix")?,
        size_greater_than: size(
            given.object_size_greater_than_bytes,
            "ObjectSizeGreaterThanBytes",
        )?,
        size_less_than: size(given.object_size_less_than_bytes, "ObjectSizeLessThanBytes")?,
        storage_classes: listed(
            given.match_any_storage_class,
            &STORAGE_CLASSES,
            "MatchAnyStorageClass",
        )?,
        encryption,
        replication_statuses: listed(
            given.object_replication_statuses,
            &REPLICATION_STATUSES,
            "ObjectReplicationStatuses",
        )?,
    })
}

fn encryption_of(given: EncryptionFilterXml) -> s3s::S3Result<EncryptionFilter> {
    let mut found = Vec::new();
    if given.sse_s3.is_some() {
        found.push(EncryptionFilter::SseS3);
    }
    if let Some(kms) = given.sse_kms {
        found.push(EncryptionFilter::SseKms {
            key_arn: kms.kms_key_arn,
            bucket_key: kms.bucket_key_enabled,
        });
    }
    if let Some(dsse) = given.dsse_kms {
        found.push(EncryptionFilter::DsseKms {
            key_arn: dsse.kms_key_arn,
        });
    }
    if given.sse_c.is_some() {
        found.push(EncryptionFilter::SseC);
    }
    if given.not_sse.is_some() {
        found.push(EncryptionFilter::NotSse);
    }
    match <[EncryptionFilter; 1]>::try_from(found) {
        Ok([one]) => Ok(one),
        Err(_) => Err(bad_request(
            "An ObjectEncryption is one of SSE-S3, SSE-KMS, DSSE-KMS, SSE-C and NOT-SSE.",
        )),
    }
}

// ---- Answering `DescribeJob` --------------------------------------------------------

/// A job's `ManifestGenerator`, as S3 Control answers it.
pub(crate) fn generator_xml(generator: &ManifestGenerator) -> GeneratorXml {
    let arn = |bucket: &str| format!("arn:aws:s3:::{bucket}");
    let f = &generator.filter;
    let some = |values: &[String]| (!values.is_empty()).then(|| members(values.iter().cloned()));
    let names = KeyNameXml {
        prefixes: some(&f.prefixes),
        suffixes: some(&f.suffixes),
        substrings: some(&f.substrings),
    };
    let constrained = !(f.prefixes.is_empty() && f.suffixes.is_empty() && f.substrings.is_empty());
    let filter = FilterXml {
        eligible_for_replication: f.eligible_for_replication,
        created_after: f.created_after_ms.map(iso),
        created_before: f.created_before_ms.map(iso),
        object_replication_statuses: some(&f.replication_statuses),
        key_name_constraint: constrained.then_some(names),
        object_size_greater_than_bytes: f
            .size_greater_than
            .map(|n| i64::try_from(n).unwrap_or(i64::MAX)),
        object_size_less_than_bytes: f
            .size_less_than
            .map(|n| i64::try_from(n).unwrap_or(i64::MAX)),
        match_any_storage_class: some(&f.storage_classes),
        match_any_object_encryption: f.encryption.as_ref().map(|e| EncryptionsXml {
            items: vec![encryption_xml(e)],
        }),
    };
    GeneratorXml {
        s3: Some(S3GeneratorXml {
            expected_bucket_owner: generator.expected_bucket_owner.clone(),
            source_bucket: Some(arn(&generator.source_bucket)),
            manifest_output_location: generator.output.as_ref().map(|out| OutputXml {
                expected_manifest_bucket_owner: out.expected_owner.clone(),
                bucket: Some(arn(&out.bucket)),
                manifest_prefix: out.prefix.clone(),
                manifest_encryption: match (&out.kms_key, out.sse_s3) {
                    (Some(key), _) => Some(OutputEncryptionXml {
                        sse_s3: None,
                        sse_kms: Some(KeyIdXml {
                            key_id: key.clone(),
                        }),
                    }),
                    (None, true) => Some(OutputEncryptionXml {
                        sse_s3: Some(Empty {}),
                        sse_kms: None,
                    }),
                    (None, false) => None,
                },
                manifest_format: Some(GENERATED_FORMAT.to_owned()),
            }),
            filter: Some(filter),
            enable_manifest_output: Some(generator.output_enabled),
        }),
    }
}

fn encryption_xml(filter: &EncryptionFilter) -> EncryptionFilterXml {
    let mut xml = EncryptionFilterXml::default();
    match filter {
        EncryptionFilter::SseS3 => xml.sse_s3 = Some(Empty {}),
        EncryptionFilter::SseKms {
            key_arn,
            bucket_key,
        } => {
            xml.sse_kms = Some(KmsFilterXml {
                kms_key_arn: key_arn.clone(),
                bucket_key_enabled: *bucket_key,
            });
        }
        EncryptionFilter::DsseKms { key_arn } => {
            xml.dsse_kms = Some(KmsFilterXml {
                kms_key_arn: key_arn.clone(),
                bucket_key_enabled: None,
            });
        }
        EncryptionFilter::SseC => xml.sse_c = Some(Empty {}),
        EncryptionFilter::NotSse => xml.not_sse = Some(Empty {}),
    }
    xml
}

/// The manifest a job wrote, as `DescribeJob` answers it.
pub(crate) fn descriptor_xml(generated: &GeneratedManifest) -> DescriptorXml {
    DescriptorXml {
        format: GENERATED_FORMAT,
        location: DescriptorLocationXml {
            object_arn: format!("arn:aws:s3:::{}/{}", generated.bucket, generated.key),
            etag: generated.etag.clone(),
        },
    }
}

// ---- Inventory reports ---------------------------------------------------------------

/// What a job needs of an inventory report's `manifest.json`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InventoryManifest {
    #[serde(default)]
    destination_bucket: Option<String>,
    file_format: String,
    file_schema: String,
    files: Vec<InventoryFile>,
}

#[derive(Debug, Deserialize)]
struct InventoryFile {
    key: String,
    #[serde(rename = "MD5checksum")]
    md5: String,
}

/// What each column of a `fileSchema` is: `Bucket`, `Key` and `VersionId`; any other
/// is ignored.
fn fields_of(schema: &str) -> Result<Vec<ManifestField>, String> {
    let fields: Vec<_> = schema
        .split(',')
        .map(|column| match column.trim() {
            "Bucket" => ManifestField::Bucket,
            "Key" => ManifestField::Key,
            "VersionId" => ManifestField::VersionId,
            _ => ManifestField::Ignore,
        })
        .collect();
    let has = |wanted| fields.contains(&wanted);
    if has(ManifestField::Bucket) && has(ManifestField::Key) {
        Ok(fields)
    } else {
        Err("its fileSchema names no Bucket or no Key column".to_owned())
    }
}

/// The data files and columns an inventory report's `manifest.json` names.
fn inventory_of(
    json: &[u8],
    manifest: &Manifest,
) -> Result<(Vec<ManifestFile>, Vec<ManifestField>), Stop> {
    let invalid = |why: &str| {
        Stop::Failed(format!(
            "InvalidManifest: The inventory report's manifest.json {why}."
        ))
    };
    let read: InventoryManifest =
        serde_json::from_slice(json).map_err(|err| invalid(&format!("can't be read: {err}")))?;
    if !read.file_format.eq_ignore_ascii_case("CSV") {
        return Err(invalid(&format!(
            "is of a {} report: S3 Batch Operations reads CSV ones",
            read.file_format
        )));
    }
    let fields = fields_of(&read.file_schema).map_err(|why| invalid(&why))?;
    let bucket = read
        .destination_bucket
        .as_deref()
        .and_then(bucket_of)
        .unwrap_or_else(|| manifest.bucket.clone());
    let files = read
        .files
        .into_iter()
        .map(|file| ManifestFile {
            bucket: bucket.clone(),
            key: file.key,
            md5: file.md5.to_ascii_lowercase(),
        })
        .collect();
    Ok((files, fields))
}

/// Reads a new job's inventory report: its data files, and how many objects they list,
/// each line checked.
pub(crate) async fn prepare_inventory(
    role: &AsRole<'_>,
    job: &mut BatchJob,
    manifest: &Manifest,
) -> Result<(), Stop> {
    let got = role
        .client
        .get_object()
        .bucket(&manifest.bucket)
        .key(&manifest.key)
        .set_version_id(manifest.version_id.clone())
        .if_match(&manifest.etag)
        .send()
        .await
        .map_err(|err| unread(&err))?;
    let json = got
        .body
        .collect()
        .await
        .map_err(|err| Stop::Later(format!("Reading the manifest failed: {err}")))?
        .into_bytes();
    let (files, fields) = inventory_of(&json, manifest)?;
    let mut total = 0;
    for (n, file) in files.iter().enumerate() {
        let lines = open(&role.client, file).await?;
        for (number, line) in (1..).zip(lines) {
            let line = line.map_err(|err| bad_line(n, number, &err.to_string()))?;
            if !line.trim().is_empty() {
                task(&line, &fields).map_err(|why| bad_line(n, number, &why))?;
                total += 1;
            }
        }
    }
    let progress = &mut job.progress;
    progress.total = Some(total);
    (progress.files, progress.fields) = (files, fields);
    (progress.file, progress.line) = (0, 0);
    Ok(())
}

fn bad_line(file: usize, line: u64, why: &str) -> Stop {
    Stop::Failed(format!(
        "InvalidManifestContent: Line {line} of the manifest's data file {} is invalid: {why}",
        file + 1
    ))
}

fn unread<
    E: aws_sdk_s3::error::ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
>(
    err: &aws_sdk_s3::error::SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> Stop {
    stop(
        err.raw_response().map(|r| r.status().as_u16()),
        format!(
            "ManifestReadFailed: Reading the manifest failed: {}",
            crate::replicator::said(err)
        ),
    )
}

/// The lines of a data file.
type Lines = std::io::Lines<BufReader<GzDecoder<Cursor<Bytes>>>>;

/// A data file's lines, read whole and checked against its MD5.
async fn open(client: &Client, file: &ManifestFile) -> Result<Lines, Stop> {
    let got = client
        .get_object()
        .bucket(&file.bucket)
        .key(&file.key)
        .send()
        .await
        .map_err(|err| unread(&err))?;
    let bytes = got
        .body
        .collect()
        .await
        .map_err(|err| Stop::Later(format!("Reading the manifest failed: {err}")))?
        .into_bytes();
    if crate::inventory::hex(&Md5::digest(&bytes)) != file.md5 {
        return Err(Stop::Failed(format!(
            "InvalidManifestContent: The manifest's data file {} doesn't match its MD5 \
             checksum.",
            file.key
        )));
    }
    Ok(BufReader::new(GzDecoder::new(Cursor::new(bytes))).lines())
}

/// The data file a job is reading, kept open between its pages.
struct Open {
    job: String,
    file: usize,
    line: u64,
    lines: Lines,
}

/// The data file being read, if any: one job runs at a time.
#[derive(Clone, Default)]
pub(crate) struct Reading(Arc<Mutex<Option<Open>>>);

impl std::fmt::Debug for Reading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reading")
    }
}

impl Reading {
    fn take(&self, job: &str, file: usize, line: u64) -> Option<Lines> {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.take()
            .filter(|open| open.job == job && open.file == file && open.line == line)
            .map(|open| open.lines)
    }

    fn keep(&self, open: Open) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(open);
    }
}

/// The next tasks of a job whose objects its data files list, at most `wanted`; where
/// it then is (file and line), and whether they were the last.
pub(crate) async fn next_in_files(
    role: &AsRole<'_>,
    job: &BatchJob,
    wanted: usize,
) -> Result<(Vec<Task>, (usize, u64), bool), Stop> {
    let progress = &job.progress;
    let (mut file, mut line) = (progress.file, progress.line);
    let mut tasks = Vec::new();
    while tasks.len() < wanted {
        let Some(data) = progress.files.get(file) else {
            return Ok((tasks, (file, line), true));
        };
        let kept = role.operations.reading.take(&job.id, file, line);
        let mut lines = if let Some(lines) = kept {
            lines
        } else {
            let mut lines = open(&role.client, data).await?;
            for _ in 0..line {
                if lines.next().is_none() {
                    break;
                }
            }
            lines
        };
        let mut ended = true;
        while tasks.len() < wanted {
            // Read whole when the job was prepared, each line checked; the files don't
            // change.
            let Some(Ok(text)) = lines.next() else { break };
            line += 1;
            if !text.trim().is_empty()
                && let Ok(task) = task(&text, &progress.fields)
            {
                tasks.push(task);
            }
            if tasks.len() == wanted {
                ended = false;
            }
        }
        if ended {
            (file, line) = (file + 1, 0);
        } else {
            role.operations.reading.keep(Open {
                job: job.id.clone(),
                file,
                line,
                lines,
            });
        }
    }
    let last = file >= progress.files.len();
    Ok((tasks, (file, line), last))
}

// ---- Generated lists ---------------------------------------------------------------------

/// Whether the generator takes an object: its filter's every condition holds, and, for
/// Batch Replication, the bucket's replication rules take it (as AWS's generated
/// manifests for it hold every version the rules take).
fn takes(
    generator: &ManifestGenerator,
    replicating: bool,
    rules: Option<&ReplicationConfig>,
    info: &ObjectInfo,
) -> bool {
    let f = &generator.filter;
    let key = info.key.as_str();
    let modified = crate::admin::millis(info.modified);
    let kms = info
        .sse
        .as_ref()
        .is_some_and(|sse| matches!(sse.mode, SseMode::Kms | SseMode::Dsse));
    let eligible =
        || rules.is_some_and(|rules| !rules.destinations(key, &info.attrs.tags, kms).is_empty());
    let any = |values: &[String], test: &dyn Fn(&str) -> bool| {
        values.is_empty() || values.iter().any(|v| test(v))
    };
    let status = info
        .attrs
        .replication
        .as_ref()
        .map_or("NONE", |r| r.status.as_str());
    f.created_after_ms.is_none_or(|after| modified > after)
        && f.created_before_ms.is_none_or(|before| modified < before)
        && f.size_greater_than.is_none_or(|n| info.size > n)
        && f.size_less_than.is_none_or(|n| info.size < n)
        && any(&f.prefixes, &|p| key.starts_with(p))
        && any(&f.substrings, &|s| key.contains(s))
        && any(&f.suffixes, &|s| key.ends_with(s))
        // Every object TeiFS keeps is STANDARD.
        && any(&f.storage_classes, &|class| class == "STANDARD")
        && any(&f.replication_statuses, &|wanted| wanted == status)
        && f.encryption.as_ref().is_none_or(|e| encrypted(e, info))
        && f.eligible_for_replication.is_none_or(|wanted| eligible() == wanted)
        && (!replicating || eligible())
}

/// Whether an object is encrypted as `filter` says.
fn encrypted(filter: &EncryptionFilter, info: &ObjectInfo) -> bool {
    let sse = info.sse.as_ref();
    let key_is = |wanted: &Option<String>, sse: &teifs_types::SseInfo| {
        wanted.as_ref().is_none_or(|wanted| {
            sse.kms_key
                .as_ref()
                .is_some_and(|key| wanted == key || wanted.ends_with(&format!("/{key}")))
        })
    };
    match (filter, sse) {
        (EncryptionFilter::NotSse, None) => true,
        (EncryptionFilter::SseS3, Some(sse)) => sse.mode == SseMode::S3,
        (EncryptionFilter::SseC, Some(sse)) => sse.mode == SseMode::Customer,
        (
            EncryptionFilter::SseKms {
                key_arn,
                bucket_key,
            },
            Some(sse),
        ) => {
            sse.mode == SseMode::Kms
                && key_is(key_arn, sse)
                && bucket_key.is_none_or(|wanted| sse.bucket_key == wanted)
        }
        (EncryptionFilter::DsseKms { key_arn }, Some(sse)) => {
            sse.mode == SseMode::Dsse && key_is(key_arn, sse)
        }
        _ => false,
    }
}

/// Where a generated list goes on from: after this key, and version when every version
/// is listed.
type ListedAt = (String, Option<String>);

/// A page of the source bucket's objects the generator takes, each with where a list
/// goes on from after it, and where the next page starts (none after the last).
async fn list_page(
    store: &Store,
    (generator, spec): (&ManifestGenerator, &OperationJob),
    rules: Option<&ReplicationConfig>,
    listed_ms: i64,
    after: Option<ListedAt>,
) -> Result<(Vec<(Task, ListedAt)>, Option<ListedAt>), Stop> {
    let bucket = &generator.source_bucket;
    let replicating = matches!(spec.operation, Operation::ReplicateObject);
    // Every object it takes starts with its key prefix filter's prefix.
    let prefix = generator
        .filter
        .prefixes
        .first()
        .cloned()
        .unwrap_or_default();
    let failed = |err: teifs_store::StoreError| match err {
        teifs_store::StoreError::NoSuchBucket => {
            Stop::Failed("NoSuchBucket: The generator's source bucket doesn't exist.".to_owned())
        }
        err => Stop::Later(format!("Listing the source bucket failed: {err}")),
    };
    // Written before the job listed its objects: what it lists when it starts.
    let listed = |info: &ObjectInfo| crate::admin::millis(info.modified) <= listed_ms;
    let task_of = |info: &ObjectInfo| Task {
        bucket: bucket.clone(),
        key: info.key.clone(),
        version: info.version_id.clone().filter(|v| v != "null"),
    };
    if replicating {
        let (key_marker, version_marker) = after.map_or((None, None), |(k, v)| (Some(k), v));
        let listing = store
            .list_versions(
                bucket,
                VersionsQuery {
                    prefix,
                    delimiter: None,
                    key_marker,
                    version_marker,
                    max_keys: LIST_PAGE,
                },
            )
            .await
            .map_err(failed)?;
        let found = listing
            .versions
            .iter()
            .filter(|v| {
                !v.delete_marker && listed(&v.info) && takes(generator, true, rules, &v.info)
            })
            .map(|v| {
                let at = (v.info.key.clone(), v.info.version_id.clone());
                (task_of(&v.info), at)
            })
            .collect();
        let next = listing.next.filter(|_| listing.truncated);
        return Ok((found, next));
    }
    let listing = store
        .list(
            bucket,
            ListQuery {
                prefix,
                delimiter: None,
                after: after.map(|(key, _)| After::Key(key)),
                max_keys: LIST_PAGE,
            },
        )
        .await
        .map_err(failed)?;
    let found = listing
        .objects
        .iter()
        .filter(|info| listed(info) && takes(generator, false, rules, info))
        .map(|info| (task_of(info), (info.key.clone(), None)))
        .collect();
    let next = match listing.next.filter(|_| listing.truncated) {
        Some(After::Key(key) | After::Prefix(key)) => Some((key, None)),
        None => None,
    };
    Ok((found, next))
}

/// Whether the job's role may list the source bucket, and the bucket is the account's
/// it's expected to be.
async fn may_list(
    role: &AsRole<'_>,
    generator: &ManifestGenerator,
    replicating: bool,
) -> Result<(), Stop> {
    let operations = role.operations;
    let account = operations.iam.account();
    let owners = [
        generator.expected_bucket_owner.as_ref(),
        generator
            .output
            .as_ref()
            .and_then(|o| o.expected_owner.as_ref()),
    ];
    if owners.into_iter().flatten().any(|owner| *owner != account) {
        return Err(Stop::Failed(
            "AccessDenied: A bucket of the job isn't owned by the account it's expected to be."
                .to_owned(),
        ));
    }
    let rules = operations.rules.of(&generator.source_bucket).await.ok();
    let context = access::base_context(
        &role.identity,
        &http::HeaderMap::new(),
        crate::Client {
            ip: None,
            secure: true,
            tls: None,
        },
        &account,
    );
    let action = if replicating {
        "s3:ListBucketVersions"
    } else {
        "s3:ListBucket"
    };
    if access::allows(
        &role.identity,
        &context,
        action,
        &teifs_policy::bucket_arn(&generator.source_bucket),
        rules.as_deref(),
    ) {
        Ok(())
    } else {
        Err(Stop::Failed(format!(
            "AccessDenied: The job's role may not list the source bucket ({action})."
        )))
    }
}

/// Lists a new job's objects: counts them, and writes them as a manifest when asked.
pub(crate) async fn prepare_generated(
    role: &AsRole<'_>,
    store: &Store,
    job: &mut BatchJob,
    (generator, spec): (&ManifestGenerator, &OperationJob),
) -> Result<(), Stop> {
    let replicating = matches!(spec.operation, Operation::ReplicateObject);
    may_list(role, generator, replicating).await?;
    let rules = store
        .bucket_replication(&generator.source_bucket)
        .await
        .ok()
        .flatten();
    let listed_ms = crate::admin::millis(std::time::SystemTime::now());
    let output = generator
        .output
        .as_ref()
        .filter(|_| generator.output_enabled);
    let mut writer = output.map(|output| Writer::new(output, &job.id));
    let (mut total, mut after) = (0_u64, None);
    loop {
        let (found, next) =
            list_page(store, (generator, spec), rules.as_deref(), listed_ms, after).await?;
        total += found.len() as u64;
        if let Some(writer) = &mut writer {
            for (task, _) in &found {
                writer.push(&role.client, task).await?;
            }
        }
        match next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    let progress = &mut job.progress;
    progress.total = Some(total);
    (progress.file, progress.line) = (0, 0);
    if let Some(writer) = writer {
        let (files, generated) = writer
            .finish(&role.client, &generator.source_bucket)
            .await?;
        progress.files = files;
        progress.fields = vec![
            ManifestField::Bucket,
            ManifestField::Key,
            ManifestField::VersionId,
        ];
        progress.generated = Some(generated);
    } else {
        progress.listed_ms = Some(listed_ms);
        (progress.last_key, progress.last_version) = (None, None);
    }
    Ok(())
}

/// The next tasks of a job that keeps its list to itself, at most `wanted`; where it
/// then goes on from, and whether they were the last.
pub(crate) async fn next_listed(
    store: &Store,
    job: &BatchJob,
    (generator, spec): (&ManifestGenerator, &OperationJob),
    wanted: usize,
) -> Result<(Vec<Task>, Option<ListedAt>, bool), Stop> {
    let rules = store
        .bucket_replication(&generator.source_bucket)
        .await
        .ok()
        .flatten();
    let listed_ms = job.progress.listed_ms.unwrap_or(i64::MAX);
    let mut after = job
        .progress
        .last_key
        .clone()
        .map(|key| (key, job.progress.last_version.clone()));
    let mut tasks = Vec::new();
    loop {
        let (found, next) = list_page(
            store,
            (generator, spec),
            rules.as_deref(),
            listed_ms,
            after.clone(),
        )
        .await?;
        for (task, at) in found {
            if tasks.len() == wanted {
                return Ok((tasks, after, false));
            }
            tasks.push(task);
            after = Some(at);
        }
        match next {
            Some(next) if tasks.len() < wanted => after = Some(next),
            Some(_) => return Ok((tasks, after, false)),
            None => return Ok((tasks, after, true)),
        }
    }
}

/// Writes a generated manifest: gzipped CSV data files, then `manifest.json` and
/// `manifest.checksum`, under `{prefix}/job-{id}/generated/`.
struct Writer<'a> {
    output: &'a ManifestOutput,
    base: String,
    csv: Option<GzEncoder<Vec<u8>>>,
    lines: u64,
    files: Vec<ManifestFile>,
    sizes: Vec<usize>,
}

impl<'a> Writer<'a> {
    fn new(output: &'a ManifestOutput, id: &str) -> Self {
        let prefix = output
            .prefix
            .as_deref()
            .unwrap_or_default()
            .trim_end_matches('/');
        let base = if prefix.is_empty() {
            format!("job-{id}/generated")
        } else {
            format!("{prefix}/job-{id}/generated")
        };
        Self {
            output,
            base,
            csv: None,
            lines: 0,
            files: Vec::new(),
            sizes: Vec::new(),
        }
    }

    async fn push(&mut self, client: &Client, task: &Task) -> Result<(), Stop> {
        use std::io::Write as _;
        let csv = self
            .csv
            .get_or_insert_with(|| GzEncoder::new(Vec::new(), Compression::default()));
        let line = format!(
            "\"{}\",\"{}\",\"{}\"\n",
            task.bucket.replace('"', "\"\""),
            crate::encode::url(&task.key),
            task.version
                .as_deref()
                .unwrap_or_default()
                .replace('"', "\"\""),
        );
        csv.write_all(line.as_bytes())
            .map_err(|err| Stop::Later(err.to_string()))?;
        self.lines += 1;
        if self.lines >= LINES_PER_FILE {
            self.flush(client).await?;
        }
        Ok(())
    }

    /// Writes the data file being filled, if any.
    async fn flush(&mut self, client: &Client) -> Result<(), Stop> {
        let Some(csv) = self.csv.take() else {
            return Ok(());
        };
        let data = csv.finish().map_err(|err| Stop::Later(err.to_string()))?;
        let key = format!("{}/data/{}.csv.gz", self.base, uuid::Uuid::new_v4());
        let md5 = crate::inventory::hex(&Md5::digest(&data));
        self.sizes.push(data.len());
        self.put(client, &key, "application/x-gzip", data).await?;
        self.files.push(ManifestFile {
            bucket: self.output.bucket.clone(),
            key,
            md5,
        });
        self.lines = 0;
        Ok(())
    }

    async fn put(
        &self,
        client: &Client,
        key: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<String, Stop> {
        let mut put = client
            .put_object()
            .bucket(&self.output.bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(body));
        if let Some(kms) = &self.output.kms_key {
            put = put
                .server_side_encryption(ServerSideEncryption::AwsKms)
                .ssekms_key_id(kms);
        } else if self.output.sse_s3 {
            put = put.server_side_encryption(ServerSideEncryption::Aes256);
        }
        put.storage_class(StorageClass::Standard)
            .send()
            .await
            .map(|out| out.e_tag.unwrap_or_default())
            .map_err(|err| {
                stop(
                    err.raw_response().map(|r| r.status().as_u16()),
                    format!(
                        "ManifestWriteFailed: Writing the generated manifest failed: {}",
                        crate::replicator::said(&err)
                    ),
                )
            })
    }

    /// Writes the last data file and the manifest; the files, and the manifest.
    async fn finish(
        mut self,
        client: &Client,
        source: &str,
    ) -> Result<(Vec<ManifestFile>, GeneratedManifest), Stop> {
        self.flush(client).await?;
        let files: Vec<_> = self
            .files
            .iter()
            .zip(&self.sizes)
            .map(|(file, size)| {
                serde_json::json!({"key": file.key, "size": size, "MD5checksum": file.md5})
            })
            .collect();
        let manifest = serde_json::json!({
            "sourceBucket": source,
            "destinationBucket": format!("arn:aws:s3:::{}", self.output.bucket),
            "version": "2016-11-30",
            "creationTimestamp": crate::admin::millis(std::time::SystemTime::now()).to_string(),
            "fileFormat": "CSV",
            "fileSchema": GENERATED_SCHEMA,
            "files": files,
        })
        .to_string()
        .into_bytes();
        let checksum = crate::inventory::hex(&Md5::digest(&manifest));
        let key = format!("{}/manifest.json", self.base);
        let etag = self.put(client, &key, "application/json", manifest).await?;
        let checksum_key = format!("{}/manifest.checksum", self.base);
        self.put(client, &checksum_key, "text/plain", checksum.into_bytes())
            .await?;
        let generated = GeneratedManifest {
            bucket: self.output.bucket.clone(),
            key,
            etag,
        };
        Ok((self.files, generated))
    }
}

#[cfg(test)]
mod tests {
    use teifs_types::SseInfo;

    use super::*;

    fn read(xml: &str) -> s3s::S3Result<ManifestGenerator> {
        let given: GeneratorXml = quick_xml::de::from_str(xml).unwrap();
        generator_of(given)
    }

    const OUTPUT: &str = "<ManifestOutputLocation><Bucket>arn:aws:s3:::lists</Bucket>\
        <ManifestPrefix>made</ManifestPrefix><ManifestEncryption><SSE-KMS><KeyId>k1</KeyId>\
        </SSE-KMS></ManifestEncryption><ManifestFormat>S3InventoryReport_CSV_20211130\
        </ManifestFormat></ManifestOutputLocation>";

    #[test]
    fn generators_are_read_as_s3_control_writes_them() {
        let xml = format!(
            "<ManifestGenerator><S3JobManifestGenerator>\
             <ExpectedBucketOwner>123456789012</ExpectedBucketOwner>\
             <SourceBucket>arn:aws:s3:::photos</SourceBucket>{OUTPUT}\
             <Filter><EligibleForReplication>true</EligibleForReplication>\
             <CreatedAfter>2026-01-02T03:04:05Z</CreatedAfter>\
             <ObjectReplicationStatuses><member>NONE</member><member>FAILED</member></ObjectReplicationStatuses>\
             <KeyNameConstraint><MatchAnyPrefix><member>2026/</member></MatchAnyPrefix>\
             <MatchAnySuffix><member>.jpg</member></MatchAnySuffix></KeyNameConstraint>\
             <ObjectSizeGreaterThanBytes>10</ObjectSizeGreaterThanBytes>\
             <MatchAnyStorageClass><member>STANDARD</member></MatchAnyStorageClass>\
             <MatchAnyObjectEncryption><ObjectEncryption><SSE-KMS><KmsKeyArn>arn:aws:kms:us-east-1:1:key/k</KmsKeyArn>\
             <BucketKeyEnabled>true</BucketKeyEnabled></SSE-KMS></ObjectEncryption></MatchAnyObjectEncryption>\
             </Filter><EnableManifestOutput>true</EnableManifestOutput>\
             </S3JobManifestGenerator></ManifestGenerator>"
        );
        let read = read(&xml).unwrap();
        assert_eq!(read.source_bucket, "photos");
        assert_eq!(read.expected_bucket_owner.as_deref(), Some("123456789012"));
        assert!(read.output_enabled);
        let output = read.output.clone().unwrap();
        assert_eq!(output.bucket, "lists");
        assert_eq!(output.prefix.as_deref(), Some("made"));
        assert_eq!(output.kms_key.as_deref(), Some("k1"));
        let f = &read.filter;
        assert_eq!(f.created_after_ms, Some(1_767_323_045_000));
        assert_eq!(f.prefixes, ["2026/"]);
        assert_eq!(f.suffixes, [".jpg"]);
        assert_eq!(f.replication_statuses, ["NONE", "FAILED"]);
        assert_eq!(f.size_greater_than, Some(10));
        assert_eq!(f.eligible_for_replication, Some(true));
        assert_eq!(
            f.encryption,
            Some(EncryptionFilter::SseKms {
                key_arn: Some("arn:aws:kms:us-east-1:1:key/k".to_owned()),
                bucket_key: Some(true),
            })
        );
        // Answered as it was given.
        let again =
            quick_xml::se::to_string_with_root("ManifestGenerator", &generator_xml(&read)).unwrap();
        let again: GeneratorXml = quick_xml::de::from_str(&again).unwrap();
        assert_eq!(generator_of(again).unwrap(), read);
    }

    #[test]
    fn wrong_generators_are_refused() {
        let wrap = |inner: &str| {
            format!(
                "<ManifestGenerator><S3JobManifestGenerator>{inner}</S3JobManifestGenerator>\
                 </ManifestGenerator>"
            )
        };
        let source = "<SourceBucket>arn:aws:s3:::photos</SourceBucket>";
        let off = "<EnableManifestOutput>false</EnableManifestOutput>";
        assert!(read(&wrap(&format!("{source}{off}"))).is_ok());
        for wrong in [
            String::new(),
            off.to_owned(),
            source.to_owned(),
            format!("<SourceBucket>photos</SourceBucket>{off}"),
            format!("<SourceBucket>arn:aws:s3:::photos/a</SourceBucket>{off}"),
            format!("{source}<EnableManifestOutput>true</EnableManifestOutput>"),
            format!("{source}{off}<ExpectedBucketOwner>12</ExpectedBucketOwner>"),
            format!(
                "{source}{off}<Filter><MatchAnyStorageClass><member>COLD</member></MatchAnyStorageClass></Filter>"
            ),
            format!(
                "{source}{off}<Filter><ObjectReplicationStatuses><member>PENDING</member></ObjectReplicationStatuses></Filter>"
            ),
            format!(
                "{source}{off}<Filter><KeyNameConstraint><MatchAnyPrefix><member>a</member><member>b</member></MatchAnyPrefix></KeyNameConstraint></Filter>"
            ),
            format!(
                "{source}{off}<Filter><KeyNameConstraint><MatchAnySuffix><member></member></MatchAnySuffix></KeyNameConstraint></Filter>"
            ),
            format!(
                "{source}{off}<Filter><ObjectSizeLessThanBytes>-1</ObjectSizeLessThanBytes></Filter>"
            ),
            format!("{source}{off}<Filter><CreatedBefore>soon</CreatedBefore></Filter>"),
            format!(
                "{source}{off}<Filter><MatchAnyObjectEncryption><ObjectEncryption><SSE-S3/><SSE-C/></ObjectEncryption></MatchAnyObjectEncryption></Filter>"
            ),
            format!(
                "{source}{off}<Filter><MatchAnyObjectEncryption></MatchAnyObjectEncryption></Filter>"
            ),
            format!("{source}{off}{}", OUTPUT.replace("20211130", "20161130")),
            format!("{source}{off}{}", OUTPUT.replace("<KeyId>k1</KeyId>", "")),
        ] {
            assert_eq!(
                read(&wrap(&wrong)).map(|_| ()).unwrap_err().code().as_str(),
                "BadRequestException",
                "{wrong}"
            );
        }
    }

    #[test]
    fn an_inventory_reports_schema_says_where_bucket_key_and_version_are() {
        assert_eq!(
            fields_of("Bucket, Key, VersionId, IsLatest, IsDeleteMarker, Size"),
            Ok(vec![
                ManifestField::Bucket,
                ManifestField::Key,
                ManifestField::VersionId,
                ManifestField::Ignore,
                ManifestField::Ignore,
                ManifestField::Ignore,
            ])
        );
        assert!(fields_of("Bucket, Size").is_err());
        let manifest = Manifest {
            format: teifs_types::batch::ManifestFormat::Inventory,
            bucket: "reports".to_owned(),
            key: "inv/manifest.json".to_owned(),
            version_id: None,
            etag: "\"e\"".to_owned(),
            fields: Vec::new(),
        };
        let json = br#"{"sourceBucket":"photos","destinationBucket":"arn:aws:s3:::inventory",
            "version":"2016-11-30","fileFormat":"CSV","fileSchema":"Bucket, Key",
            "files":[{"key":"d/1.csv.gz","size":3,"MD5checksum":"ABC"}]}"#;
        let (files, fields) = inventory_of(json, &manifest).unwrap();
        assert_eq!(
            files,
            [ManifestFile {
                bucket: "inventory".to_owned(),
                key: "d/1.csv.gz".to_owned(),
                md5: "abc".to_owned(),
            }]
        );
        assert_eq!(fields, [ManifestField::Bucket, ManifestField::Key]);
        let orc = String::from_utf8_lossy(json).replace("\"CSV\"", "\"ORC\"");
        assert!(matches!(
            inventory_of(orc.as_bytes(), &manifest),
            Err(Stop::Failed(_))
        ));
        assert!(matches!(
            inventory_of(b"{}", &manifest),
            Err(Stop::Failed(_))
        ));
    }

    fn object(key: &str, size: u64, sse: Option<SseMode>) -> ObjectInfo {
        ObjectInfo {
            key: key.to_owned(),
            size,
            modified: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000),
            etag: String::new(),
            attrs: teifs_types::ObjectAttrs::default(),
            parts: Vec::new(),
            version_id: None,
            sse: sse.map(|mode| SseInfo {
                mode,
                kms_key: Some("k".to_owned()),
                customer_key_md5: None,
                bucket_key: false,
            }),
        }
    }

    #[test]
    fn the_filter_takes_objects_whose_every_condition_holds() {
        let mut generator = ManifestGenerator::default();
        let takes_ = |g: &ManifestGenerator, info: &ObjectInfo| takes(g, false, None, info);
        let photo = object("2026/a.jpg", 100, None);
        assert!(takes_(&generator, &photo));
        generator.filter.prefixes = vec!["2026/".to_owned()];
        generator.filter.suffixes = vec![".jpg".to_owned()];
        generator.filter.size_greater_than = Some(99);
        generator.filter.created_before_ms = Some(1_000_001);
        generator.filter.replication_statuses = vec!["NONE".to_owned()];
        generator.filter.storage_classes = vec!["STANDARD".to_owned()];
        assert!(takes_(&generator, &photo));
        assert!(!takes_(&generator, &object("2025/a.jpg", 100, None)));
        assert!(!takes_(&generator, &object("2026/a.png", 100, None)));
        assert!(!takes_(&generator, &object("2026/a.jpg", 99, None)));
        generator.filter.created_after_ms = Some(1_000_000);
        assert!(!takes_(&generator, &photo));
        generator.filter = GeneratorFilter {
            storage_classes: vec!["GLACIER".to_owned()],
            ..GeneratorFilter::default()
        };
        assert!(!takes_(&generator, &photo));
        generator.filter = GeneratorFilter {
            eligible_for_replication: Some(true),
            ..GeneratorFilter::default()
        };
        assert!(!takes_(&generator, &photo));
        generator.filter.eligible_for_replication = Some(false);
        assert!(takes_(&generator, &photo));
        // Batch Replication takes only what the rules take.
        assert!(!takes(&ManifestGenerator::default(), true, None, &photo));
    }

    #[test]
    fn objects_are_taken_by_how_they_are_encrypted() {
        let plain = object("a", 1, None);
        let s3 = object("a", 1, Some(SseMode::S3));
        let kms = object("a", 1, Some(SseMode::Kms));
        assert!(encrypted(&EncryptionFilter::NotSse, &plain));
        assert!(!encrypted(&EncryptionFilter::NotSse, &s3));
        assert!(encrypted(&EncryptionFilter::SseS3, &s3));
        assert!(!encrypted(&EncryptionFilter::SseS3, &kms));
        let with = |key: Option<&str>, bucket_key| EncryptionFilter::SseKms {
            key_arn: key.map(str::to_owned),
            bucket_key,
        };
        assert!(encrypted(&with(None, None), &kms));
        assert!(encrypted(
            &with(Some("arn:aws:kms:us-east-1:1:key/k"), Some(false)),
            &kms
        ));
        assert!(!encrypted(
            &with(Some("arn:aws:kms:us-east-1:1:key/x"), None),
            &kms
        ));
        assert!(!encrypted(&with(None, Some(true)), &kms));
        assert!(!encrypted(&EncryptionFilter::SseC, &kms));
    }
}
