//! `MinIO`'s `replicate` batch job: copies the versions under a source's prefixes that
//! its filter takes to a target, a page at a time. One end is a bucket here, the other a
//! bucket on another S3 service, reached as replication reaches its targets
//! ([`crate::replicator`]). Pushed versions go with `MinIO`'s replica headers, so another
//! TeiFS or a `MinIO` keeps their ids and times; pulled ones are written here as
//! replicas, with theirs. When either end is plain S3, each key's current object goes,
//! as a new version.

use std::{future::Future, time::Duration};

use aws_sdk_s3::{
    error::{ProvideErrorMetadata, SdkError},
    operation::get_object::GetObjectOutput,
    primitives::DateTime,
    types::{ObjectLockLegalHoldStatus, ObjectLockMode, ServerSideEncryption},
};
use http::StatusCode;
use s3s::S3Error;
use teifs_store::{
    JobSecrets, ObjectVersion, Precondition, Replica, Store, StoreError, Versioning, filter_takes,
};
use teifs_types::{
    LockMode, ObjectAttrs, ObjectInfo, Retention, SseInfo, SseMode,
    batch::{BatchJob, JobRetry, ReplicateEnd, ReplicateJob, VersionFilter},
};

use crate::{
    admin,
    errors::StoreResultExt,
    minio_iam::invalid,
    replicator::{CHUNK, Connection, Missed, Remote, Sending, is_aws, replica_encryption, said},
};

/// How many keys (pushed) or versions (pulled) a page takes.
const PAGE: usize = 1_000;

/// What became of a version.
enum Outcome {
    /// Copied: its bytes.
    Copied(u64),
    /// Gone meanwhile, or not one the filter takes after all.
    Passed,
}

/// The other service's host (`HOST[:PORT]`) in `endpoint`.
fn host(endpoint: &str) -> &str {
    let rest = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest)
}

/// The region requests to `endpoint` are signed for: an AWS endpoint's own, else
/// `us-east-1`.
fn region(endpoint: &str) -> String {
    let host = host(endpoint);
    let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if is_aws(&host) {
        let labels: Vec<&str> = host.split('.').collect();
        for (at, label) in labels.iter().enumerate() {
            if let Some(region) = label.strip_prefix("s3-") {
                return region.to_owned();
            }
            if *label == "s3" {
                let next = labels[at + 1..]
                    .iter()
                    .find(|l| !matches!(**l, "dualstack" | "accesspoint"));
                if let Some(next) = next.filter(|l| **l != "amazonaws") {
                    return (*next).to_owned();
                }
            }
        }
    }
    "us-east-1".to_owned()
}

/// A client for the job's other end, signed in with `secrets`; `replica_headers` when
/// pushed versions keep their ids.
pub(crate) fn connect(job: &ReplicateJob, secrets: &JobSecrets, replica_headers: bool) -> Remote {
    let far = if job.source.remote.is_some() {
        &job.source
    } else {
        &job.target
    };
    let remote = far.remote.as_ref();
    let endpoint = remote.map(|r| r.endpoint.clone()).unwrap_or_default();
    let aws = is_aws(host(&endpoint));
    Remote::connect(Connection {
        region: region(&endpoint),
        access_key: remote.map_or("", |r| r.access_key.as_str()),
        secret_key: secrets.secret_key.as_ref().map_or("", |s| s.as_str()),
        session_token: secrets.session_token.as_ref().map(|s| s.as_str()),
        bucket: far.bucket.clone(),
        path_style: path_style(remote.and_then(|r| r.path_style), aws),
        storage_class: None,
        replica_headers: replica_headers && !aws,
        endpoint,
    })
}

/// Whether buckets are named in the path: as `given`, else (`auto`) in the host on AWS
/// and the path elsewhere.
const fn path_style(given: Option<bool>, aws: bool) -> bool {
    match given {
        Some(given) => given,
        None => !aws,
    }
}

/// The key `key` is copied to: under the target's prefix.
fn target_key(job: &ReplicateJob, key: &str) -> String {
    match job.target.prefixes.first().map(|p| p.trim_end_matches('/')) {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}/{key}"),
        _ => key.to_owned(),
    }
}

/// The prefixes the source is walked under.
fn prefixes(end: &ReplicateEnd) -> Vec<String> {
    if end.prefixes.is_empty() {
        vec![String::new()]
    } else {
        end.prefixes.clone()
    }
}

/// Checks, as a job is started, that both buckets are there and the other end lets these
/// keys in, and (when versions keep their ids) that the target keeps versions if the
/// source does.
pub(crate) async fn check(
    store: &Store,
    job: &ReplicateJob,
    secrets: &JobSecrets,
) -> Result<(), S3Error> {
    let pushed = job.source.remote.is_none();
    let here = job.here();
    let versioning = match store.bucket_versioning(&here.bucket).await {
        Err(StoreError::NoSuchBucket) => {
            return Err(admin::error(
                StatusCode::NOT_FOUND,
                "NoSuchSourceBucket",
                format!("The specified bucket {} does not exist", here.bucket),
            ));
        }
        other => other.s3()?,
    };
    let remote = connect(job, secrets, false);
    let answer = remote
        .client()
        .get_bucket_versioning()
        .bucket(remote.bucket())
        .send()
        .await;
    let remote_versioned = match answer {
        Ok(out) => out.status() == Some(&aws_sdk_s3::types::BucketVersioningStatus::Enabled),
        Err(err) if err.code() == Some("NoSuchBucket") => {
            return Err(admin::error(
                StatusCode::NOT_FOUND,
                "NoSuchTargetBucket",
                "The specified target bucket does not exist",
            ));
        }
        Err(err) => {
            return Err(invalid(format!(
                "Invalid batch replication: the bucket {} at {} can't be reached: {}",
                remote.bucket(),
                job.source
                    .remote
                    .as_ref()
                    .or(job.target.remote.as_ref())
                    .map_or("", |r| r.endpoint.as_str()),
                said(&err)
            )));
        }
    };
    let here_versioned = versioning == Versioning::Enabled;
    let mismatched = if pushed {
        here_versioned && !remote_versioned
    } else {
        !here_versioned && remote_versioned
    };
    if job.keeps_versions() && mismatched {
        return Err(admin::error(
            StatusCode::BAD_REQUEST,
            "InvalidBucketState",
            format!(
                "The source '{}' has versioning enabled, target '{}' must have versioning enabled",
                job.source.bucket, job.target.bucket
            ),
        ));
    }
    Ok(())
}

/// Runs the next page of `job`, a `replicate` job, from where its progress says,
/// counting what it copied and what it couldn't; whether the job is done. A failure of
/// the page as a whole (a listing) is the drive's error, or an I/O one for the other
/// service.
pub(crate) async fn page(
    store: &Store,
    job: &mut BatchJob,
    spec: &ReplicateJob,
    secrets: &JobSecrets,
) -> Result<bool, StoreError> {
    let prefixes = prefixes(&spec.source);
    let Some(prefix) = prefixes.get(job.progress.prefix).cloned() else {
        return Ok(true);
    };
    let more = if spec.source.remote.is_none() {
        push_page(store, job, spec, secrets, &prefix).await?
    } else {
        pull_page(store, job, spec, secrets, &prefix).await?
    };
    if !more {
        job.progress.prefix += 1;
        job.progress.last_key = None;
        job.progress.last_version = None;
    }
    Ok(job.progress.prefix >= prefixes.len())
}

/// Sends a page of the keys here; whether there are more under `prefix`.
async fn push_page(
    store: &Store,
    job: &mut BatchJob,
    spec: &ReplicateJob,
    secrets: &JobSecrets,
    prefix: &str,
) -> Result<bool, StoreError> {
    let bucket = &spec.source.bucket;
    let keeps =
        spec.keeps_versions() && store.bucket_versioning(bucket).await? != Versioning::Unversioned;
    let remote = connect(spec, secrets, keeps);
    let now = crate::inventory::now_ms();
    let (versions, more) = store
        .whole_keys(bucket, prefix, job.progress.last_key.clone(), PAGE)
        .await?;
    for key_versions in versions.chunk_by(|a, b| a.info.key == b.info.key) {
        // Oldest first, so the target's current version is the source's.
        let chosen: Vec<&ObjectVersion> = if keeps {
            key_versions.iter().rev().collect()
        } else {
            key_versions
                .first()
                .filter(|newest| !newest.delete_marker)
                .into_iter()
                .collect()
        };
        for version in chosen {
            if filter_takes(&spec.filter, version, now) {
                let pushed = retried(spec.retry, &mut job.progress.retry_attempts, || {
                    push(store, spec, &remote, version)
                })
                .await;
                count(job, version, pushed);
            }
        }
        job.progress.last_key = Some(key_versions[0].info.key.clone());
    }
    Ok(more)
}

/// Sends a version (or delete marker) here to the target.
async fn push(
    store: &Store,
    spec: &ReplicateJob,
    remote: &Remote,
    version: &ObjectVersion,
) -> Result<Outcome, Missed> {
    let (bucket, key) = (&spec.source.bucket, &version.info.key);
    let to = target_key(spec, key);
    let version_id = version.info.version_id.as_deref().unwrap_or("null");
    if version.delete_marker {
        let replica = Replica {
            version_id: version_id.to_owned(),
            modified_ms: admin::millis(version.info.modified),
            etag: None,
        };
        remote.send_marker(&to, &replica).await?;
        return Ok(Outcome::Copied(0));
    }
    let sse = version.info.sse.as_ref();
    if sse.is_some_and(|sse| sse.mode == SseMode::Customer) {
        return Err(Missed::Failed(
            "the server doesn't hold an SSE-C object's key".to_owned(),
        ));
    }
    let (info, body) = match store.read_with(bucket, key, Some(version_id), None).await {
        Ok(read) => read,
        // Removed meanwhile: there's nothing left to send.
        Err(StoreError::NoSuchKey | StoreError::NoSuchVersion) => return Ok(Outcome::Passed),
        Err(err) => return Err(err.into()),
    };
    let size = info.size;
    let replica = Replica {
        version_id: version_id.to_owned(),
        modified_ms: admin::millis(info.modified),
        etag: Some(info.etag.clone()),
    };
    remote
        .send(Sending {
            store,
            bucket,
            key,
            target_key: &to,
            info,
            body,
            replica,
            replica_key: None,
            storage_class: None,
        })
        .await?;
    Ok(Outcome::Copied(size))
}

/// A version (or delete marker) another service listed.
struct Listed {
    key: String,
    version_id: Option<String>,
    modified: Option<DateTime>,
    size: u64,
    delete_marker: bool,
}

impl Listed {
    /// It as a version here, without what a listing doesn't say (tags, metadata).
    fn version(&self) -> ObjectVersion {
        ObjectVersion {
            info: ObjectInfo {
                key: self.key.clone(),
                size: self.size,
                modified: time(self.modified.as_ref()),
                etag: String::new(),
                attrs: ObjectAttrs::default(),
                sse: None,
                parts: Vec::new(),
                version_id: self.version_id.clone(),
            },
            latest: false,
            delete_marker: self.delete_marker,
        }
    }
}

fn time(at: Option<&DateTime>) -> std::time::SystemTime {
    at.and_then(|at| std::time::SystemTime::try_from(*at).ok())
        .unwrap_or(std::time::UNIX_EPOCH)
}

/// Copies a page of the other service's versions here; whether there are more under
/// `prefix`.
async fn pull_page(
    store: &Store,
    job: &mut BatchJob,
    spec: &ReplicateJob,
    secrets: &JobSecrets,
    prefix: &str,
) -> Result<bool, StoreError> {
    let remote = connect(spec, secrets, false);
    let keeps = spec.keeps_versions();
    let (listed, next) = list(&remote, prefix, &job.progress, keeps).await?;
    let now = crate::inventory::now_ms();
    // What a listing can say: the rest is looked at once the version is read.
    let ages = VersionFilter {
        tags: Vec::new(),
        metadata: Vec::new(),
        ..spec.filter.clone()
    };
    for entry in &listed {
        let version = entry.version();
        let wanted = if entry.delete_marker {
            filter_takes(&spec.filter, &version, now)
        } else {
            filter_takes(&ages, &version, now)
        };
        if wanted {
            let pulled = retried(spec.retry, &mut job.progress.retry_attempts, || {
                pull(store, spec, &remote, entry, now)
            })
            .await;
            count(job, &version, pulled);
        }
    }
    let more = next.is_some();
    if let Some((key, version)) = next {
        job.progress.last_key = Some(key);
        job.progress.last_version = version;
    }
    Ok(more)
}

/// A page of the other service's versions (`keeps`) or current objects under `prefix`,
/// oldest first for each key, and where the next starts, if there's one.
async fn list(
    remote: &Remote,
    prefix: &str,
    progress: &teifs_types::batch::JobProgress,
    keeps: bool,
) -> Result<(Vec<Listed>, Option<(String, Option<String>)>), StoreError> {
    let most = i32::try_from(PAGE).unwrap_or(i32::MAX);
    let size = |s: Option<i64>| u64::try_from(s.unwrap_or_default()).unwrap_or_default();
    if keeps {
        let out = remote
            .client()
            .list_object_versions()
            .bucket(remote.bucket())
            .prefix(prefix)
            .max_keys(most)
            .set_key_marker(progress.last_key.clone())
            .set_version_id_marker(progress.last_version.clone())
            .send()
            .await
            .map_err(|err| listing_failed(&err))?;
        let mut listed: Vec<Listed> = out
            .versions()
            .iter()
            .map(|v| Listed {
                key: v.key().unwrap_or_default().to_owned(),
                version_id: v.version_id().map(str::to_owned),
                modified: v.last_modified().copied(),
                size: size(v.size()),
                delete_marker: false,
            })
            .chain(out.delete_markers().iter().map(|m| Listed {
                key: m.key().unwrap_or_default().to_owned(),
                version_id: m.version_id().map(str::to_owned),
                modified: m.last_modified().copied(),
                size: 0,
                delete_marker: true,
            }))
            .collect();
        listed.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| time(a.modified.as_ref()).cmp(&time(b.modified.as_ref())))
        });
        let next = out
            .is_truncated()
            .unwrap_or_default()
            .then(|| out.next_key_marker().map(str::to_owned))
            .flatten()
            .map(|key| (key, out.next_version_id_marker().map(str::to_owned)));
        Ok((listed, next))
    } else {
        let out = remote
            .client()
            .list_objects_v2()
            .bucket(remote.bucket())
            .prefix(prefix)
            .max_keys(most)
            .set_start_after(progress.last_key.clone())
            .send()
            .await
            .map_err(|err| listing_failed(&err))?;
        let listed: Vec<Listed> = out
            .contents()
            .iter()
            .map(|o| Listed {
                key: o.key().unwrap_or_default().to_owned(),
                version_id: None,
                modified: o.last_modified().copied(),
                size: size(o.size()),
                delete_marker: false,
            })
            .collect();
        let next = out
            .is_truncated()
            .unwrap_or_default()
            .then(|| listed.last().map(|last| (last.key.clone(), None)))
            .flatten();
        Ok((listed, next))
    }
}

/// A listing's failure, as the page's: the bucket gone, or the service not answering.
fn listing_failed<E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static>(
    err: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> StoreError {
    if err.code() == Some("NoSuchBucket") {
        return StoreError::NoSuchBucket;
    }
    StoreError::Io(std::io::Error::other(format!(
        "the other service's listing failed: {}",
        said(err)
    )))
}

/// Copies a version (or delete marker) of the other service's here.
async fn pull(
    store: &Store,
    spec: &ReplicateJob,
    remote: &Remote,
    entry: &Listed,
    now: i64,
) -> Result<Outcome, Missed> {
    let to = target_key(spec, &entry.key);
    let bucket = &spec.target.bucket;
    // The version's identity, where it's kept (a `null` version has none to keep).
    let identity = entry
        .version_id
        .as_ref()
        .filter(|id| spec.keeps_versions() && id.as_str() != "null")
        .map(|id| Replica {
            version_id: id.clone(),
            modified_ms: admin::millis(time(entry.modified.as_ref())),
            etag: None,
        });
    if entry.delete_marker {
        if let Some(replica) = identity {
            store.commit_replica_marker(bucket, &to, replica).await?;
            return Ok(Outcome::Copied(0));
        }
        return Ok(Outcome::Passed);
    }
    let answer = remote
        .client()
        .get_object()
        .bucket(remote.bucket())
        .key(&entry.key)
        .set_version_id(identity.as_ref().map(|r| r.version_id.clone()))
        .send()
        .await;
    let mut out = match answer {
        Ok(out) => out,
        // Removed meanwhile: there's nothing left to copy.
        Err(err)
            if err
                .raw_response()
                .is_some_and(|r| r.status().as_u16() == 404) =>
        {
            return Ok(Outcome::Passed);
        }
        Err(err) => return Err(crate::replicator::missed(&err)),
    };
    let mut info = info_of(&entry.key, &out);
    if out.tag_count().unwrap_or_default() > 0 {
        let tags = remote
            .client()
            .get_object_tagging()
            .bucket(remote.bucket())
            .key(&entry.key)
            .set_version_id(identity.as_ref().map(|r| r.version_id.clone()))
            .send()
            .await
            .map_err(|err| crate::replicator::missed(&err))?;
        info.attrs.tags = tags
            .tag_set()
            .iter()
            .map(|tag| (tag.key().to_owned(), tag.value().to_owned()))
            .collect();
    }
    let version = ObjectVersion {
        info,
        latest: false,
        delete_marker: false,
    };
    if !filter_takes(&spec.filter, &version, now) {
        return Ok(Outcome::Passed);
    }
    let written = write_here(store, (bucket, &to), version.info, &mut out.body, identity).await?;
    Ok(Outcome::Copied(written))
}

/// Writes a version of the other service's, `info`, read from `body`, to `to` (a bucket
/// and key here): as a replica with its identity, where it's kept. How many bytes.
async fn write_here(
    store: &Store,
    (bucket, to): (&str, &str),
    info: ObjectInfo,
    body: &mut aws_sdk_s3::primitives::ByteStream,
    identity: Option<Replica>,
) -> Result<u64, Missed> {
    let mode = info.sse.as_ref().map(|sse| sse.mode);
    let encryption = replica_encryption(store, bucket, mode, None).await?;
    let mut staged = store.stage_for(bucket, &encryption).await?;
    let mut written = 0;
    loop {
        let chunk = body
            .try_next()
            .await
            .map_err(|err| Missed::Later(err.to_string()))?;
        let Some(chunk) = chunk else { break };
        for piece in chunk.chunks(CHUNK) {
            staged.write(piece).await?;
        }
        written += chunk.len() as u64;
    }
    let mut attrs = info.attrs;
    attrs.replication = None;
    match identity {
        Some(mut replica) => {
            replica.etag = Some(info.etag);
            store
                .commit_replica(bucket, to, staged, attrs, replica)
                .await?;
        }
        None => {
            store
                .commit(bucket, to, staged, attrs, Precondition::default())
                .await?;
        }
    }
    Ok(written)
}

/// What a `GetObject` answer says of the version, besides its bytes and tags.
fn info_of(key: &str, out: &GetObjectOutput) -> ObjectInfo {
    let owned = |s: Option<&str>| s.map(str::to_owned);
    let retention = match (out.object_lock_mode(), out.object_lock_retain_until_date()) {
        (Some(mode), Some(until)) => {
            let mode = match mode {
                ObjectLockMode::Compliance => Some(LockMode::Compliance),
                ObjectLockMode::Governance => Some(LockMode::Governance),
                _ => None,
            };
            mode.map(|mode| Retention {
                mode,
                until_ms: admin::millis(time(Some(until))),
            })
        }
        _ => None,
    };
    let legal_hold = out
        .object_lock_legal_hold_status()
        .map(|status| *status == ObjectLockLegalHoldStatus::On);
    let mode = match out.server_side_encryption() {
        Some(ServerSideEncryption::Aes256) => Some(SseMode::S3),
        Some(ServerSideEncryption::AwsKms) => Some(SseMode::Kms),
        Some(ServerSideEncryption::AwsKmsDsse) => Some(SseMode::Dsse),
        _ => None,
    };
    ObjectInfo {
        key: key.to_owned(),
        size: u64::try_from(out.content_length().unwrap_or_default()).unwrap_or_default(),
        modified: time(out.last_modified()),
        etag: out.e_tag().unwrap_or_default().trim_matches('"').to_owned(),
        attrs: ObjectAttrs {
            content_type: owned(out.content_type()),
            content_encoding: owned(out.content_encoding()),
            content_disposition: owned(out.content_disposition()),
            content_language: owned(out.content_language()),
            cache_control: owned(out.cache_control()),
            expires: owned(out.expires_string()),
            website_redirect_location: owned(out.website_redirect_location()),
            user: out
                .metadata()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default(),
            retention,
            legal_hold,
            ..ObjectAttrs::default()
        },
        sse: mode.map(|mode| SseInfo {
            mode,
            kms_key: None,
            customer_key_md5: None,
            bucket_key: false,
        }),
        parts: Vec::new(),
        version_id: out.version_id().map(str::to_owned),
    }
}

/// Runs `attempt` until it succeeds, fails for good, or has been tried as often as
/// `retry` says, counting the retries in `retries`.
async fn retried<T, F: Future<Output = Result<T, Missed>>>(
    retry: JobRetry,
    retries: &mut u32,
    mut attempt: impl FnMut() -> F,
) -> Result<T, Missed> {
    let mut tried = 1;
    loop {
        match attempt().await {
            Err(Missed::Later(_) | Missed::Unreachable(_)) if tried < retry.attempts.max(1) => {
                *retries += 1;
                tried += 1;
                tokio::time::sleep(Duration::from_millis(retry.delay_ms)).await;
            }
            other => return other,
        }
    }
}

/// Counts what became of `version` in `job`'s progress.
fn count(job: &mut BatchJob, version: &ObjectVersion, result: Result<Outcome, Missed>) {
    let progress = &mut job.progress;
    let size = version.info.size;
    match result {
        Ok(Outcome::Copied(bytes)) => {
            if version.delete_marker {
                progress.delete_markers += 1;
            } else {
                progress.objects += 1;
                progress.bytes += bytes;
            }
        }
        Ok(Outcome::Passed) => {}
        Err(Missed::Failed(why) | Missed::Later(why) | Missed::Unreachable(why)) => {
            if version.delete_marker {
                progress.delete_markers_failed += 1;
            } else {
                progress.objects_failed += 1;
                progress.bytes_failed += size;
            }
            let id = version.info.version_id.as_deref().unwrap_or("null");
            job.failed_because(format!("{} ({id}): {why}", version.info.key));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_signed_for_an_aws_endpoints_region() {
        assert_eq!(region("https://s3.eu-west-2.amazonaws.com"), "eu-west-2");
        assert_eq!(region("https://s3-ap-south-1.amazonaws.com"), "ap-south-1");
        assert_eq!(
            region("https://s3.dualstack.us-west-2.amazonaws.com/"),
            "us-west-2"
        );
        assert_eq!(region("https://s3.amazonaws.com"), "us-east-1");
        assert_eq!(region("http://backup.example.com:9000"), "us-east-1");
        assert_eq!(region("http://s3.eu-west-2.example.com"), "us-east-1");
    }

    #[test]
    fn buckets_are_named_in_the_host_on_aws_unless_told() {
        assert!(path_style(None, false));
        assert!(!path_style(None, true));
        assert!(path_style(Some(true), true));
        assert!(!path_style(Some(false), false));
    }

    #[test]
    fn keys_go_under_the_targets_prefix() {
        let end = |prefixes: &[&str]| ReplicateEnd {
            kind: teifs_types::batch::EndKind::Minio,
            bucket: "b".to_owned(),
            prefixes: prefixes.iter().map(|p| (*p).to_owned()).collect(),
            remote: None,
        };
        let job = |target| ReplicateJob {
            source: end(&[]),
            target,
            filter: VersionFilter::default(),
            notify: None,
            retry: JobRetry::default(),
        };
        assert_eq!(target_key(&job(end(&[])), "a/b"), "a/b");
        assert_eq!(target_key(&job(end(&[""])), "a/b"), "a/b");
        assert_eq!(target_key(&job(end(&["copy"])), "a/b"), "copy/a/b");
        assert_eq!(target_key(&job(end(&["copy/"])), "a"), "copy/a");
        assert_eq!(prefixes(&end(&[])), [""]);
        assert_eq!(prefixes(&end(&["x/", "y/"])), ["x/", "y/"]);
        assert_eq!(
            host("https://h.example.com:9000/path"),
            "h.example.com:9000"
        );
        assert_eq!(host("h.example.com"), "h.example.com");
    }
}
