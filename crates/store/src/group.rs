//! Group commit: writes and deletes waiting for the commit lock are recorded together.
//! Whoever gets the lock records every one waiting then, in one transaction, so one sync
//! of the index covers them all; the others find theirs done when they get it. Each is
//! still checked on its own (its precondition sees the changes recorded before it in the
//! group), and one that fails leaves the others alone. Data files the changes free are
//! removed only once the transaction is committed.

use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Instant,
};

use teifs_meta::Index;
use teifs_types::ObjectAttrs;

use crate::{
    Bucket, Inner, ObjectInfo, Precondition, StoreError,
    error::Result,
    objects::{Deleted, ObjectBucket, Written},
    stages,
};

/// What a recorded change did.
enum Done {
    Written(Box<ObjectInfo>),
    Deleted(Deleted),
}

/// A change's answer, filled in by whoever records it.
type Answer = Arc<Mutex<Option<Result<Done>>>>;

/// A change waiting to be recorded.
enum Job {
    /// An object bucket's data file, already in place ([`Inner::write_object`]).
    Object {
        bucket: String,
        bucket_id: String,
        written: Box<Written>,
    },
    /// A folder bucket's file, synced, to be renamed into place as `key`.
    File {
        bucket: String,
        key: String,
        tmp: PathBuf,
        etag: String,
        attrs: Box<ObjectAttrs>,
    },
    /// A delete in an object bucket ([`Inner::delete_object`]), or of one version of a
    /// key ([`Inner::delete_object_version`]).
    Delete {
        bucket: String,
        bucket_id: String,
        key: String,
        version_id: Option<String>,
        bypass: bool,
    },
}

struct Waiting {
    job: Job,
    precondition: Precondition,
    answer: Answer,
}

/// What a recorded change leaves to do once the group's transaction is committed: the
/// data files no version refers to any more, in the store that holds them.
type Recorded = (Done, Vec<String>, Option<ObjectBucket>);

/// The changes waiting for the commit lock.
#[derive(Default)]
pub(crate) struct Group {
    waiting: Mutex<Vec<Waiting>>,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("waiting", &self.waiting().len())
            .finish()
    }
}

impl Group {
    fn waiting(&self) -> MutexGuard<'_, Vec<Waiting>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many changes are waiting.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.waiting().len()
    }
}

fn take(answer: &Answer) -> Option<Result<Done>> {
    answer.lock().unwrap_or_else(PoisonError::into_inner).take()
}

fn give(answer: &Answer, result: Result<Done>) {
    *answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
}

/// The error each change of a group gets when the group's transaction fails.
fn shared(err: &StoreError) -> StoreError {
    if err.is_storage_full() {
        StoreError::StorageFull
    } else {
        StoreError::Io(io::Error::other(err.to_string()))
    }
}

/// A change's answer, when it was lost (never filled in, or of the wrong kind).
fn lost() -> StoreError {
    StoreError::Io(io::Error::other("the change was lost while being recorded"))
}

/// A write's answer.
fn as_written(done: Done) -> Result<ObjectInfo> {
    match done {
        Done::Written(info) => Ok(*info),
        Done::Deleted(_) => Err(lost()),
    }
}

impl Inner {
    /// Records `written` (put in place by [`Inner::write_object`] for the object bucket
    /// `bucket_id`, named `bucket`) as the current version of its key, with whatever
    /// other writes are waiting.
    pub(crate) fn record_grouped(
        &self,
        bucket: &str,
        bucket_id: &str,
        written: Written,
        precondition: Precondition,
    ) -> Result<ObjectInfo> {
        let job = Job::Object {
            bucket: bucket.to_owned(),
            bucket_id: bucket_id.to_owned(),
            written: Box::new(written),
        };
        self.grouped(job, precondition).and_then(as_written)
    }

    /// Renames the synced file `tmp` into place as `key` in the folder bucket `bucket`
    /// and records it ([`Inner::commit_file`]), with whatever other writes are waiting.
    pub(crate) fn place_grouped(
        &self,
        bucket: &str,
        key: &str,
        tmp: PathBuf,
        etag: String,
        attrs: ObjectAttrs,
        precondition: Precondition,
    ) -> Result<ObjectInfo> {
        let job = Job::File {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            tmp,
            etag,
            attrs: Box::new(attrs),
        };
        self.grouped(job, precondition).and_then(as_written)
    }

    /// Deletes `key` (or its version `version_id`) in the object bucket `bucket_id`,
    /// named `bucket`, with whatever other changes are waiting.
    pub(crate) fn delete_grouped(
        &self,
        bucket: &str,
        bucket_id: &str,
        key: &str,
        version_id: Option<&str>,
        precondition: Precondition,
        bypass: bool,
    ) -> Result<Deleted> {
        let job = Job::Delete {
            bucket: bucket.to_owned(),
            bucket_id: bucket_id.to_owned(),
            key: key.to_owned(),
            version_id: version_id.map(str::to_owned),
            bypass,
        };
        match self.grouped(job, precondition)? {
            Done::Deleted(deleted) => Ok(deleted),
            Done::Written(_) => Err(lost()),
        }
    }

    fn grouped(&self, job: Job, precondition: Precondition) -> Result<Done> {
        let answer = Answer::default();
        self.group.waiting().push(Waiting {
            job,
            precondition,
            answer: answer.clone(),
        });
        let waited = Instant::now();
        let conn = self.lock();
        stages::record(&self.stages, "write", "lock", waited);
        // Whoever had the lock before may have recorded this write with theirs.
        if let Some(result) = take(&answer) {
            return result;
        }
        // Else it's still waiting (it was added before the lock was taken, and a group
        // is taken and answered under the lock): record it and everything waiting.
        let since = Instant::now();
        let group = std::mem::take(&mut *self.group.waiting());
        self.record_group(&conn, group);
        stages::record(&self.stages, "write", "commit", since);
        drop(conn);
        take(&answer).unwrap_or_else(|| Err(lost()))
    }

    /// Records a group of writes in one transaction and answers each. Holds the commit
    /// lock (`conn`).
    fn record_group(&self, conn: &Index, group: Vec<Waiting>) {
        let mut recorded = Vec::with_capacity(group.len());
        let outcome = conn.try_batch(|conn| -> Result<()> {
            for Waiting {
                job,
                precondition,
                answer,
            } in group
            {
                // An object bucket's file isn't anyone's until it's recorded, so it goes
                // if the transaction fails; a folder bucket's is in place by then.
                let unrecorded = match &job {
                    Job::Object { written, .. } => Some(written.path().to_owned()),
                    Job::File { .. } | Job::Delete { .. } => None,
                };
                let result = self.record_job(conn, job, &precondition);
                recorded.push((answer, unrecorded, result));
            }
            Ok(())
        });
        match outcome {
            Ok(()) => {
                // The replaced files go once their rows are gone for good.
                let _ = conn.try_batch(|conn| -> Result<()> {
                    for (_, _, result) in &recorded {
                        if let Ok((_, replaced, Some(store))) = result {
                            Inner::remove_data_files(conn, store, replaced);
                        }
                    }
                    Ok(())
                });
                for (answer, _, result) in recorded {
                    give(&answer, result.map(|(info, ..)| info));
                }
            }
            Err(err) => {
                for (answer, unrecorded, result) in recorded {
                    if let (Ok(_), Some(path)) = (&result, unrecorded) {
                        let _ = std::fs::remove_file(path);
                    }
                    give(&answer, result.and(Err(shared(&err))));
                }
            }
        }
    }

    /// Records one write of a group in its own savepoint: one that fails is undone alone.
    fn record_job(&self, conn: &Index, job: Job, precondition: &Precondition) -> Result<Recorded> {
        match job {
            Job::Object {
                bucket,
                bucket_id,
                written,
            } => {
                let bucket = match self.object_bucket(&bucket, &bucket_id) {
                    Ok(bucket) => bucket,
                    Err(err) => {
                        written.discard();
                        return Err(err);
                    }
                };
                let (info, replaced) =
                    conn.try_batch(|conn| self.record_row(conn, &bucket, *written, precondition))?;
                Ok((Done::Written(Box::new(info)), replaced, Some(bucket)))
            }
            Job::File {
                bucket,
                key,
                tmp,
                etag,
                attrs,
            } => {
                // The bucket may have gone since the write began.
                let Bucket::Folder(bucket) = self.bucket(&bucket)? else {
                    return Err(StoreError::NoSuchBucket);
                };
                let key = self.new_key(&key)?;
                let (info, replaced) = conn.try_batch(|conn| {
                    self.place_file(conn, &bucket, &key, &tmp, etag, *attrs, None, precondition)
                })?;
                Ok((
                    Done::Written(Box::new(info)),
                    replaced,
                    bucket.versioned().cloned(),
                ))
            }
            Job::Delete {
                bucket,
                bucket_id,
                key,
                version_id,
                bypass,
            } => {
                let bucket = self.object_bucket(&bucket, &bucket_id)?;
                let (deleted, files) = conn.try_batch(|conn| match &version_id {
                    None => Inner::delete_object(conn, &bucket, &key, precondition),
                    Some(id) => {
                        Inner::delete_object_version(conn, &bucket, &key, id, precondition, bypass)
                    }
                })?;
                Ok((Done::Deleted(deleted), files, Some(bucket)))
            }
        }
    }

    /// The object bucket `name` if it's still the one with id `id` (it may have been
    /// deleted, and its folder with it, since the change began).
    pub(crate) fn object_bucket(&self, name: &str, id: &str) -> Result<ObjectBucket> {
        match self.bucket(name) {
            Ok(Bucket::Object(bucket)) if bucket.id == id => Ok(bucket),
            Ok(_) => Err(StoreError::NoSuchBucket),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
impl Inner {
    /// Records `writes` (bucket name, its id, the write, its precondition) as one group.
    pub(crate) fn record_all(
        &self,
        writes: Vec<(String, String, Written, Precondition)>,
    ) -> Vec<Result<ObjectInfo>> {
        let group: Vec<Waiting> = writes
            .into_iter()
            .map(|(bucket, bucket_id, written, precondition)| Waiting {
                job: Job::Object {
                    bucket,
                    bucket_id,
                    written: Box::new(written),
                },
                precondition,
                answer: Answer::default(),
            })
            .collect();
        let answers: Vec<Answer> = group.iter().map(|w| w.answer.clone()).collect();
        self.record_group(&self.lock(), group);
        answers
            .iter()
            .map(|answer| {
                take(answer)
                    .expect("every write is answered")
                    .and_then(as_written)
            })
            .collect()
    }
}
