//! S3 Batch Operations' `S3PutObjectCopy`: each object is copied with `CopyObject`, as
//! the job's role, to the target bucket, under the target prefix (`Folder1` and `a/b`
//! make `Folder1/a/b`), with the options S3 Control's `S3CopyObjectOperation` gives.
//!
//! New metadata replaces the source's unless `MetadataDirective` says otherwise; new
//! tags replace the source's (an empty set: none). Event holds aren't kept by TeiFS, so a
//! job that asks for one is refused.

use std::collections::HashMap;

use aws_sdk_s3::{
    Client,
    operation::copy_object::builders::CopyObjectFluentBuilder,
    primitives::DateTime,
    types::{
        ChecksumAlgorithm, MetadataDirective, ObjectCannedAcl, ObjectLockLegalHoldStatus,
        ObjectLockMode, RequestPayer, ServerSideEncryption, StorageClass, TaggingDirective,
    },
};
use s3s::S3Result;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use teifs_types::batch::{CopyMetadata, CopyOperation, Grant, KeyValue};

use crate::{
    batch_operations::{Failure, Task},
    control_jobs::{
        Members, TagXml, bad_request, iso, members, millis_of, not_implemented, tags_of,
    },
};

pub(crate) const CANNED_ACLS: [&str; 7] = [
    "private",
    "public-read",
    "public-read-write",
    "aws-exec-read",
    "authenticated-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
];

const STORAGE_CLASSES: [&str; 7] = [
    "STANDARD",
    "STANDARD_IA",
    "ONEZONE_IA",
    "GLACIER",
    "INTELLIGENT_TIERING",
    "DEEP_ARCHIVE",
    "GLACIER_IR",
];

const CHECKSUMS: [&str; 10] = [
    "CRC32",
    "CRC32C",
    "SHA1",
    "SHA256",
    "CRC64NVME",
    "SHA512",
    "MD5",
    "XXHASH64",
    "XXHASH3",
    "XXHASH128",
];

/// How many user metadata entries a copy may be given.
const MAX_USER_METADATA: usize = 8192;

/// A job's `S3PutObjectCopy`, as S3 Control writes it.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CopyXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    target_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canned_access_control_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_control_grants: Option<Members<GrantXml>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_directive: Option<String>,
    #[serde(skip_serializing)]
    annotation_directive: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_since_constraint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_object_metadata: Option<MetadataXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_object_tagging: Option<Members<TagXml>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_pays: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_class: Option<String>,
    #[serde(
        rename = "UnModifiedSinceConstraint",
        skip_serializing_if = "Option::is_none"
    )]
    unmodified_since_constraint: Option<String>,
    #[serde(rename = "SSEAwsKmsKeyId", skip_serializing_if = "Option::is_none")]
    sse_aws_kms_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_key_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_lock_legal_hold_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_lock_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_lock_retain_until_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_key_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum_algorithm: Option<String>,
    #[serde(skip_serializing)]
    object_lock_event_hold: Option<String>,
    #[serde(skip_serializing)]
    object_lock_event_hold_duration: Option<IgnoredAny>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct GrantXml {
    grantee: Option<GranteeXml>,
    permission: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct GranteeXml {
    type_identifier: Option<String>,
    identifier: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MetadataXml {
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_metadata: Option<EntriesXml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_expires_date: Option<String>,
    #[serde(rename = "SSEAlgorithm", skip_serializing_if = "Option::is_none")]
    sse_algorithm: Option<String>,
}

/// A map, as S3 Control writes them.
#[derive(Debug, Default, Serialize, Deserialize)]
struct EntriesXml {
    #[serde(default)]
    entry: Vec<EntryXml>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EntryXml {
    key: String,
    #[serde(default)]
    value: String,
}

/// Checks a job's copy.
pub(crate) fn parse(given: CopyXml) -> S3Result<CopyOperation> {
    check(&given)?;
    let target = given.target_resource.unwrap_or_default();
    if target.starts_with("arn:aws:s3express:") {
        return Err(not_implemented("TeiFS has no directory buckets."));
    }
    let target_bucket = target
        .strip_prefix("arn:aws:s3:::")
        .filter(|bucket| !bucket.is_empty() && !bucket.contains('/'))
        .ok_or_else(|| bad_request("S3PutObjectCopy's TargetResource is a bucket's ARN."))?
        .to_owned();
    let retain_until_ms = given
        .object_lock_retain_until_date
        .as_deref()
        .map(|date| millis_of(date, "ObjectLockRetainUntilDate"))
        .transpose()?;
    if given.object_lock_mode.is_some() != retain_until_ms.is_some() {
        return Err(bad_request(
            "A copy's ObjectLockMode and ObjectLockRetainUntilDate go together.",
        ));
    }
    Ok(CopyOperation {
        target_bucket,
        target_prefix: given.target_key_prefix,
        canned_acl: given.canned_access_control_list,
        grants: grants_of(given.access_control_grants.unwrap_or_default())?,
        metadata_directive: given.metadata_directive,
        modified_since_ms: given
            .modified_since_constraint
            .as_deref()
            .map(|date| millis_of(date, "ModifiedSinceConstraint"))
            .transpose()?,
        unmodified_since_ms: given
            .unmodified_since_constraint
            .as_deref()
            .map(|date| millis_of(date, "UnModifiedSinceConstraint"))
            .transpose()?,
        metadata: given.new_object_metadata.map(metadata_of).transpose()?,
        tags: given.new_object_tagging.map(tags_of).transpose()?,
        redirect_location: given.redirect_location,
        requester_pays: given.requester_pays.unwrap_or(false),
        storage_class: given.storage_class,
        kms_key_id: given.sse_aws_kms_key_id,
        bucket_key_enabled: given.bucket_key_enabled.unwrap_or(false),
        checksum_algorithm: given.checksum_algorithm,
        legal_hold: given
            .object_lock_legal_hold_status
            .map(|status| status == "ON"),
        lock_mode: given.object_lock_mode,
        retain_until_ms,
    })
}

/// Checks the copy's choices and lengths.
fn check(given: &CopyXml) -> S3Result<()> {
    let hold = given.object_lock_event_hold.as_deref();
    one_of("ObjectLockEventHold", hold, &["ON", "OFF"])?;
    if hold == Some("ON") || given.object_lock_event_hold_duration.is_some() {
        return Err(not_implemented(
            "TeiFS doesn't keep event holds: leave out ObjectLockEventHold.",
        ));
    }
    if let Some(prefix) = &given.target_key_prefix
        && !(1..=1024).contains(&prefix.len())
    {
        return Err(bad_request("TargetKeyPrefix is 1 to 1,024 bytes."));
    }
    one_of(
        "CannedAccessControlList",
        given.canned_access_control_list.as_deref(),
        &CANNED_ACLS,
    )?;
    one_of(
        "MetadataDirective",
        given.metadata_directive.as_deref(),
        &["COPY", "REPLACE"],
    )?;
    one_of(
        "AnnotationDirective",
        given.annotation_directive.as_deref(),
        &["COPY", "EXCLUDE"],
    )?;
    one_of(
        "StorageClass",
        given.storage_class.as_deref(),
        &STORAGE_CLASSES,
    )?;
    one_of(
        "ChecksumAlgorithm",
        given.checksum_algorithm.as_deref(),
        &CHECKSUMS,
    )?;
    one_of(
        "ObjectLockLegalHoldStatus",
        given.object_lock_legal_hold_status.as_deref(),
        &["ON", "OFF"],
    )?;
    one_of(
        "ObjectLockMode",
        given.object_lock_mode.as_deref(),
        &["GOVERNANCE", "COMPLIANCE"],
    )?;
    if given
        .redirect_location
        .as_ref()
        .is_some_and(|r| !(1..=2048).contains(&r.len()))
    {
        return Err(bad_request("RedirectLocation is 1 to 2,048 bytes."));
    }
    Ok(())
}

/// Fails unless `value`, when given, is one of `allowed`.
pub(crate) fn one_of(name: &str, value: Option<&str>, allowed: &[&str]) -> S3Result<()> {
    match value {
        Some(value) if !allowed.contains(&value) => Err(bad_request(format!(
            "{name} is one of {}.",
            allowed.join(", ")
        ))),
        _ => Ok(()),
    }
}

pub(crate) fn grants_of(given: Members<GrantXml>) -> S3Result<Vec<Grant>> {
    given
        .member
        .into_iter()
        .map(|grant| {
            let grantee = grant.grantee.unwrap_or_default();
            let kind = grantee.type_identifier.unwrap_or_default();
            let identifier = grantee.identifier.unwrap_or_default();
            let permission = grant.permission.unwrap_or_default();
            if !matches!(kind.as_str(), "id" | "emailAddress" | "uri") || identifier.is_empty() {
                return Err(bad_request(
                    "A grantee has a TypeIdentifier (id, emailAddress or uri) and an Identifier.",
                ));
            }
            if !matches!(
                permission.as_str(),
                "FULL_CONTROL" | "READ" | "READ_ACP" | "WRITE_ACP"
            ) {
                return Err(bad_request(
                    "An object's grant is FULL_CONTROL, READ, READ_ACP or WRITE_ACP.",
                ));
            }
            Ok(Grant {
                kind,
                identifier,
                permission,
            })
        })
        .collect()
}

fn metadata_of(given: MetadataXml) -> S3Result<CopyMetadata> {
    one_of(
        "SSEAlgorithm",
        given.sse_algorithm.as_deref(),
        &["AES256", "KMS"],
    )?;
    let entries = given.user_metadata.unwrap_or_default().entry;
    if entries.len() > MAX_USER_METADATA {
        return Err(bad_request(format!(
            "UserMetadata has at most {MAX_USER_METADATA} entries."
        )));
    }
    if entries
        .iter()
        .any(|e| !(1..=1024).contains(&e.key.len()) || e.value.len() > 1024)
    {
        return Err(bad_request(
            "A UserMetadata key is 1 to 1,024 bytes, its value at most 1,024.",
        ));
    }
    Ok(CopyMetadata {
        cache_control: given.cache_control,
        content_disposition: given.content_disposition,
        content_encoding: given.content_encoding,
        content_language: given.content_language,
        content_type: given.content_type,
        expires_ms: given
            .http_expires_date
            .as_deref()
            .map(|date| millis_of(date, "HttpExpiresDate"))
            .transpose()?,
        sse_algorithm: given.sse_algorithm,
        user: entries
            .into_iter()
            .map(|e| KeyValue {
                key: e.key,
                value: e.value,
            })
            .collect(),
    })
}

/// Grants, as `DescribeJob` answers them; none when there are none.
pub(crate) fn grants_xml(grants: &[Grant]) -> Option<Members<GrantXml>> {
    (!grants.is_empty()).then(|| {
        members(grants.iter().map(|grant| GrantXml {
            grantee: Some(GranteeXml {
                type_identifier: Some(grant.kind.clone()),
                identifier: Some(grant.identifier.clone()),
            }),
            permission: Some(grant.permission.clone()),
        }))
    })
}

/// A job's copy, as `DescribeJob` answers it.
pub(crate) fn xml(copy: &CopyOperation) -> CopyXml {
    CopyXml {
        target_resource: Some(format!("arn:aws:s3:::{}", copy.target_bucket)),
        canned_access_control_list: copy.canned_acl.clone(),
        access_control_grants: grants_xml(&copy.grants),
        metadata_directive: copy.metadata_directive.clone(),
        modified_since_constraint: copy.modified_since_ms.map(iso),
        new_object_metadata: copy.metadata.as_ref().map(|m| MetadataXml {
            cache_control: m.cache_control.clone(),
            content_disposition: m.content_disposition.clone(),
            content_encoding: m.content_encoding.clone(),
            content_language: m.content_language.clone(),
            user_metadata: (!m.user.is_empty()).then(|| EntriesXml {
                entry: m
                    .user
                    .iter()
                    .map(|kv| EntryXml {
                        key: kv.key.clone(),
                        value: kv.value.clone(),
                    })
                    .collect(),
            }),
            content_type: m.content_type.clone(),
            http_expires_date: m.expires_ms.map(iso),
            sse_algorithm: m.sse_algorithm.clone(),
        }),
        new_object_tagging: copy
            .tags
            .as_ref()
            .map(|tags| members(tags.iter().map(TagXml::of))),
        redirect_location: copy.redirect_location.clone(),
        requester_pays: copy.requester_pays.then_some(true),
        storage_class: copy.storage_class.clone(),
        unmodified_since_constraint: copy.unmodified_since_ms.map(iso),
        sse_aws_kms_key_id: copy.kms_key_id.clone(),
        target_key_prefix: copy.target_prefix.clone(),
        object_lock_legal_hold_status: copy
            .legal_hold
            .map(|on| if on { "ON" } else { "OFF" }.to_owned()),
        object_lock_mode: copy.lock_mode.clone(),
        object_lock_retain_until_date: copy.retain_until_ms.map(iso),
        bucket_key_enabled: copy.bucket_key_enabled.then_some(true),
        checksum_algorithm: copy.checksum_algorithm.clone(),
        ..CopyXml::default()
    }
}

/// Where a copy of `key` goes: under the prefix, with a `/` between.
fn target_key(prefix: Option<&str>, key: &str) -> String {
    match prefix {
        Some(prefix) if prefix.ends_with('/') => format!("{prefix}{key}"),
        Some(prefix) => format!("{prefix}/{key}"),
        None => key.to_owned(),
    }
}

/// `x-amz-copy-source`: the source's bucket, key and version, URL-encoded.
fn source(task: &Task) -> String {
    let mut source = format!("{}/{}", task.bucket, crate::encode::url(&task.key));
    if let Some(version) = &task.version {
        source.push_str("?versionId=");
        source.push_str(&crate::encode::url(version));
    }
    source
}

/// The grants of `permission`, as its `x-amz-grant-*` header lists them.
fn grantees(grants: &[Grant], permission: &str) -> Option<String> {
    let listed: Vec<String> = grants
        .iter()
        .filter(|grant| grant.permission == permission)
        .map(|grant| format!("{}=\"{}\"", grant.kind, grant.identifier))
        .collect();
    (!listed.is_empty()).then(|| listed.join(", "))
}

/// `x-amz-tagging`: the tags, as a query string.
fn tagging(tags: &[KeyValue]) -> String {
    const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    let encode = |s: &str| percent_encoding::utf8_percent_encode(s, UNRESERVED).to_string();
    tags.iter()
        .map(|kv| format!("{}={}", encode(&kv.key), encode(&kv.value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Copies the task's object.
pub(crate) async fn run(client: &Client, copy: &CopyOperation, task: &Task) -> Result<(), Failure> {
    request(client, copy, task)
        .send()
        .await
        .map(drop)
        .map_err(|err| Failure::of(&err))
}

/// The `CopyObject` that copies the task's object.
fn request(client: &Client, copy: &CopyOperation, task: &Task) -> CopyObjectFluentBuilder {
    let metadata = copy.metadata.as_ref();
    // New metadata replaces the source's unless the job says otherwise.
    let directive = copy
        .metadata_directive
        .clone()
        .or_else(|| metadata.map(|_| "REPLACE".to_owned()));
    let encryption = match metadata.and_then(|m| m.sse_algorithm.as_deref()) {
        Some("AES256") => Some(ServerSideEncryption::Aes256),
        Some(_) => Some(ServerSideEncryption::AwsKms),
        None => copy
            .kms_key_id
            .as_ref()
            .map(|_| ServerSideEncryption::AwsKms),
    };
    let user = metadata.filter(|m| !m.user.is_empty()).map(|m| {
        m.user
            .iter()
            .map(|kv| (kv.key.clone(), kv.value.clone()))
            .collect::<HashMap<_, _>>()
    });
    client
        .copy_object()
        .bucket(&copy.target_bucket)
        .key(target_key(copy.target_prefix.as_deref(), &task.key))
        .copy_source(source(task))
        .set_copy_source_if_modified_since(copy.modified_since_ms.map(DateTime::from_millis))
        .set_copy_source_if_unmodified_since(copy.unmodified_since_ms.map(DateTime::from_millis))
        .set_acl(copy.canned_acl.as_deref().map(ObjectCannedAcl::from))
        .set_grant_full_control(grantees(&copy.grants, "FULL_CONTROL"))
        .set_grant_read(grantees(&copy.grants, "READ"))
        .set_grant_read_acp(grantees(&copy.grants, "READ_ACP"))
        .set_grant_write_acp(grantees(&copy.grants, "WRITE_ACP"))
        .set_metadata_directive(directive.as_deref().map(MetadataDirective::from))
        .set_cache_control(metadata.and_then(|m| m.cache_control.clone()))
        .set_content_disposition(metadata.and_then(|m| m.content_disposition.clone()))
        .set_content_encoding(metadata.and_then(|m| m.content_encoding.clone()))
        .set_content_language(metadata.and_then(|m| m.content_language.clone()))
        .set_content_type(metadata.and_then(|m| m.content_type.clone()))
        .set_expires(
            metadata
                .and_then(|m| m.expires_ms)
                .map(DateTime::from_millis),
        )
        .set_metadata(user)
        .set_server_side_encryption(encryption)
        .set_ssekms_key_id(copy.kms_key_id.clone())
        .set_bucket_key_enabled(copy.bucket_key_enabled.then_some(true))
        .set_tagging_directive(copy.tags.as_ref().map(|_| TaggingDirective::Replace))
        .set_tagging(copy.tags.as_deref().map(tagging))
        .set_website_redirect_location(copy.redirect_location.clone())
        .set_request_payer(copy.requester_pays.then_some(RequestPayer::Requester))
        .set_storage_class(copy.storage_class.as_deref().map(StorageClass::from))
        .set_checksum_algorithm(
            copy.checksum_algorithm
                .as_deref()
                .map(ChecksumAlgorithm::from),
        )
        .set_object_lock_legal_hold_status(copy.legal_hold.map(|on| {
            if on {
                ObjectLockLegalHoldStatus::On
            } else {
                ObjectLockLegalHoldStatus::Off
            }
        }))
        .set_object_lock_mode(copy.lock_mode.as_deref().map(ObjectLockMode::from))
        .set_object_lock_retain_until_date(copy.retain_until_ms.map(DateTime::from_millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every option S3 Control writes, as the SDK writes it.
    const EVERYTHING: &str = r"<S3PutObjectCopy>
        <TargetResource>arn:aws:s3:::copies</TargetResource>
        <CannedAccessControlList>bucket-owner-read</CannedAccessControlList>
        <AccessControlGrants>
          <member><Grantee><TypeIdentifier>id</TypeIdentifier><Identifier>abc</Identifier>
            <DisplayName>someone</DisplayName></Grantee><Permission>READ</Permission></member>
          <member><Grantee><TypeIdentifier>uri</TypeIdentifier><Identifier>http://g</Identifier>
            </Grantee><Permission>FULL_CONTROL</Permission></member>
          <member><Grantee><TypeIdentifier>emailAddress</TypeIdentifier><Identifier>a@b.c</Identifier>
            </Grantee><Permission>WRITE_ACP</Permission></member>
        </AccessControlGrants>
        <MetadataDirective>COPY</MetadataDirective>
        <AnnotationDirective>EXCLUDE</AnnotationDirective>
        <ModifiedSinceConstraint>2026-01-02T03:04:05Z</ModifiedSinceConstraint>
        <NewObjectMetadata>
          <CacheControl>no-cache</CacheControl><ContentDisposition>inline</ContentDisposition>
          <ContentEncoding>gzip</ContentEncoding><ContentLanguage>en</ContentLanguage>
          <UserMetadata><entry><key>k</key><value>v</value></entry></UserMetadata>
          <ContentLength>5</ContentLength><ContentMD5>x</ContentMD5>
          <ContentType>text/plain</ContentType>
          <HttpExpiresDate>2027-01-02T03:04:05Z</HttpExpiresDate>
          <RequesterCharged>true</RequesterCharged><SSEAlgorithm>KMS</SSEAlgorithm>
        </NewObjectMetadata>
        <NewObjectTagging><member><Key>team</Key><Value>blue</Value></member></NewObjectTagging>
        <RedirectLocation>/elsewhere</RedirectLocation>
        <RequesterPays>true</RequesterPays>
        <StorageClass>STANDARD_IA</StorageClass>
        <UnModifiedSinceConstraint>2026-02-02T03:04:05Z</UnModifiedSinceConstraint>
        <SSEAwsKmsKeyId>arn:aws:kms:us-east-1:111122223333:key/k1</SSEAwsKmsKeyId>
        <TargetKeyPrefix>Folder1</TargetKeyPrefix>
        <ObjectLockLegalHoldStatus>ON</ObjectLockLegalHoldStatus>
        <ObjectLockMode>GOVERNANCE</ObjectLockMode>
        <ObjectLockRetainUntilDate>2027-03-02T03:04:05Z</ObjectLockRetainUntilDate>
        <BucketKeyEnabled>true</BucketKeyEnabled>
        <ChecksumAlgorithm>SHA256</ChecksumAlgorithm>
        <ObjectLockEventHold>OFF</ObjectLockEventHold>
      </S3PutObjectCopy>";

    fn parsed(text: &str) -> S3Result<CopyOperation> {
        parse(quick_xml::de::from_str(text).unwrap())
    }

    /// `EVERYTHING` with `from` replaced by `to`.
    fn changed(from: &str, to: &str) -> S3Result<CopyOperation> {
        assert!(EVERYTHING.contains(from), "{from}");
        parsed(&EVERYTHING.replace(from, to))
    }

    fn code(result: S3Result<CopyOperation>) -> String {
        result.map_or_else(|err| err.code().as_str().to_owned(), |_| "ok".to_owned())
    }

    #[test]
    fn every_option_is_kept_and_described_as_given() {
        let copy = parsed(EVERYTHING).unwrap();
        assert_eq!(copy.target_bucket, "copies");
        assert!(copy.requester_pays && copy.bucket_key_enabled);
        assert_eq!(copy.legal_hold, Some(true));
        assert_eq!(copy.grants.len(), 3);
        let metadata = copy.metadata.as_ref().unwrap();
        assert_eq!(metadata.sse_algorithm.as_deref(), Some("KMS"));
        assert_eq!(metadata.user.len(), 1);
        // Described, it reads back the same.
        let mut text = String::new();
        xml(&copy)
            .serialize(
                quick_xml::se::Serializer::with_root(&mut text, Some("S3PutObjectCopy")).unwrap(),
            )
            .unwrap();
        assert_eq!(parsed(&text).unwrap(), copy);
        // Off, and the ON a legal hold may be, are kept too.
        let off = changed(
            "<ObjectLockLegalHoldStatus>ON",
            "<ObjectLockLegalHoldStatus>OFF",
        )
        .unwrap();
        assert_eq!(off.legal_hold, Some(false));
        let plain = parsed(
            "<S3PutObjectCopy><TargetResource>arn:aws:s3:::c</TargetResource></S3PutObjectCopy>",
        )
        .unwrap();
        assert!(!plain.requester_pays && !plain.bucket_key_enabled);
        assert_eq!(
            (plain.legal_hold, plain.metadata, plain.tags),
            (None, None, None)
        );
    }

    #[test]
    fn wrong_options_are_refused() {
        for (from, to, expected) in [
            (
                "<ObjectLockEventHold>OFF",
                "<ObjectLockEventHold>ON",
                "NotImplemented",
            ),
            (
                "<ObjectLockEventHold>OFF",
                "<ObjectLockEventHold>SOON",
                "BadRequestException",
            ),
            (
                "<ObjectLockEventHold>OFF</ObjectLockEventHold>",
                "<ObjectLockEventHoldDuration><Days>1</Days></ObjectLockEventHoldDuration>",
                "NotImplemented",
            ),
            (
                "arn:aws:s3:::copies",
                "arn:aws:s3express:us-east-1:1:bucket/b--x-s3",
                "NotImplemented",
            ),
            (
                "arn:aws:s3:::copies",
                "arn:aws:s3:::",
                "BadRequestException",
            ),
            (
                "arn:aws:s3:::copies",
                "arn:aws:s3:::a/b",
                "BadRequestException",
            ),
            ("/elsewhere", "", "BadRequestException"),
            ("/elsewhere", &"r".repeat(2049), "BadRequestException"),
            (
                "<ObjectLockMode>GOVERNANCE</ObjectLockMode>",
                "",
                "BadRequestException",
            ),
            (
                "<ObjectLockRetainUntilDate>2027-03-02T03:04:05Z</ObjectLockRetainUntilDate>",
                "",
                "BadRequestException",
            ),
            (
                "<TypeIdentifier>uri",
                "<TypeIdentifier>group",
                "BadRequestException",
            ),
            ("<Identifier>abc", "<Identifier>", "BadRequestException"),
            (
                "<Permission>READ<",
                "<Permission>WRITE<",
                "BadRequestException",
            ),
            ("<key>k</key>", "<key></key>", "BadRequestException"),
            (
                "<key>k</key>",
                &format!("<key>{}</key>", "k".repeat(1025)),
                "BadRequestException",
            ),
            (
                "<value>v</value>",
                &format!("<value>{}</value>", "v".repeat(1025)),
                "BadRequestException",
            ),
            (
                "<SSEAlgorithm>KMS",
                "<SSEAlgorithm>DSSE",
                "BadRequestException",
            ),
        ] {
            assert_eq!(code(changed(from, to)), expected, "{to}");
        }
        // Just within the limits.
        let longest = format!(
            "<key>{}</key><value>{}</value>",
            "k".repeat(1024),
            "v".repeat(1024)
        );
        assert_eq!(
            code(changed("<key>k</key><value>v</value>", &longest)),
            "ok"
        );
        assert_eq!(code(changed("/elsewhere", &"r".repeat(2048))), "ok");
        let entries = |n: usize| {
            (0..n)
                .map(|i| format!("<entry><key>k{i}</key><value>v</value></entry>"))
                .collect::<Vec<_>>()
                .concat()
        };
        let many = |n| changed("<entry><key>k</key><value>v</value></entry>", &entries(n));
        assert_eq!(code(many(MAX_USER_METADATA)), "ok");
        assert_eq!(code(many(MAX_USER_METADATA + 1)), "BadRequestException");
    }

    #[test]
    fn copies_are_asked_with_every_option() {
        let client = Client::from_conf(
            aws_sdk_s3::Config::builder()
                .behavior_version_latest()
                .build(),
        );
        let task = Task {
            bucket: "photos".to_owned(),
            key: "a.jpg".to_owned(),
            version: None,
        };
        let copy = parsed(EVERYTHING).unwrap();
        let built = request(&client, &copy, &task);
        let input = built.as_input();
        assert_eq!(input.get_bucket().as_deref(), Some("copies"));
        assert_eq!(input.get_key().as_deref(), Some("Folder1/a.jpg"));
        assert_eq!(
            input.get_acl().as_ref().map(ObjectCannedAcl::as_str),
            Some("bucket-owner-read")
        );
        assert_eq!(input.get_grant_read().as_deref(), Some(r#"id="abc""#));
        assert_eq!(
            input.get_grant_full_control().as_deref(),
            Some(r#"uri="http://g""#)
        );
        assert_eq!(
            input.get_grant_write_acp().as_deref(),
            Some(r#"emailAddress="a@b.c""#)
        );
        assert_eq!(input.get_grant_read_acp(), &None);
        assert_eq!(
            input.get_metadata_directive(),
            &Some(MetadataDirective::Copy)
        );
        assert_eq!(input.get_request_payer(), &Some(RequestPayer::Requester));
        assert_eq!(input.get_bucket_key_enabled(), &Some(true));
        assert_eq!(
            input.get_ssekms_key_id().as_deref(),
            Some("arn:aws:kms:us-east-1:111122223333:key/k1")
        );
        assert_eq!(
            input.get_server_side_encryption(),
            &Some(ServerSideEncryption::AwsKms)
        );
        assert_eq!(input.get_storage_class(), &Some(StorageClass::StandardIa));
        assert_eq!(
            input.get_checksum_algorithm(),
            &Some(ChecksumAlgorithm::Sha256)
        );
        assert_eq!(input.get_cache_control().as_deref(), Some("no-cache"));
        assert_eq!(input.get_content_disposition().as_deref(), Some("inline"));
        assert_eq!(input.get_content_language().as_deref(), Some("en"));
        assert_eq!(input.get_content_type().as_deref(), Some("text/plain"));
        assert!(input.get_expires().is_some());
        assert_eq!(
            input.get_metadata().as_ref().map(|m| m["k"].as_str()),
            Some("v")
        );
        assert_eq!(input.get_tagging().as_deref(), Some("team=blue"));
        assert!(input.get_copy_source_if_unmodified_since().is_some());
        assert_eq!(
            input.get_object_lock_legal_hold_status(),
            &Some(ObjectLockLegalHoldStatus::On)
        );
        assert!(input.get_object_lock_retain_until_date().is_some());
        // A KMS key alone is SSE-KMS; nothing asked, nothing sent.
        let keyed = CopyOperation {
            target_bucket: "copies".to_owned(),
            kms_key_id: Some("k".to_owned()),
            ..CopyOperation::default()
        };
        let built = request(&client, &keyed, &task);
        let input = built.as_input();
        assert_eq!(
            input.get_server_side_encryption(),
            &Some(ServerSideEncryption::AwsKms)
        );
        assert_eq!(input.get_request_payer(), &None);
        assert_eq!(input.get_bucket_key_enabled(), &None);
        assert_eq!(input.get_metadata_directive(), &None);
        let plain = CopyOperation {
            kms_key_id: None,
            ..keyed
        };
        let built = request(&client, &plain, &task);
        assert_eq!(built.as_input().get_server_side_encryption(), &None);
    }

    #[test]
    fn copies_go_under_the_prefix() {
        assert_eq!(target_key(None, "a/b.jpg"), "a/b.jpg");
        assert_eq!(target_key(Some("Folder1"), "a/b.jpg"), "Folder1/a/b.jpg");
        assert_eq!(target_key(Some("Folder1/"), "a/b.jpg"), "Folder1/a/b.jpg");
    }

    #[test]
    fn sources_are_encoded_with_their_version() {
        let task = |version: Option<&str>| Task {
            bucket: "photos".to_owned(),
            key: "a b/ü+.jpg".to_owned(),
            version: version.map(str::to_owned),
        };
        assert_eq!(source(&task(None)), "photos/a%20b/%C3%BC%2B.jpg");
        assert_eq!(
            source(&task(Some("v 1"))),
            "photos/a%20b/%C3%BC%2B.jpg?versionId=v%201"
        );
    }

    #[test]
    fn grants_are_listed_by_permission() {
        let grant = |kind: &str, identifier: &str, permission: &str| Grant {
            kind: kind.to_owned(),
            identifier: identifier.to_owned(),
            permission: permission.to_owned(),
        };
        let grants = [
            grant("id", "abc", "READ"),
            grant(
                "uri",
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "READ",
            ),
            grant("emailAddress", "a@example.com", "FULL_CONTROL"),
        ];
        assert_eq!(
            grantees(&grants, "READ").as_deref(),
            Some(r#"id="abc", uri="http://acs.amazonaws.com/groups/global/AllUsers""#)
        );
        assert_eq!(
            grantees(&grants, "FULL_CONTROL").as_deref(),
            Some(r#"emailAddress="a@example.com""#)
        );
        assert_eq!(grantees(&grants, "WRITE_ACP"), None);
    }

    #[test]
    fn tags_are_a_query_string() {
        let tags = [
            KeyValue {
                key: "team".to_owned(),
                value: "blue green".to_owned(),
            },
            KeyValue {
                key: "a&b".to_owned(),
                value: "=".to_owned(),
            },
        ];
        assert_eq!(tagging(&tags), "team=blue%20green&a%26b=%3D");
        assert_eq!(tagging(&[]), "");
    }
}
