//! Entry points for the fuzz targets in `fuzz/` (the `fuzzing` feature): the parsers that
//! read what a request sends, each called as the server calls it. Not an API: nothing
//! but the fuzz targets uses it, and it may change with them.

use s3s::{
    dto,
    xml::{Deserialize, Deserializer},
};
use teifs_types::{batch::ManifestField, notify::TargetArn};

use crate::{
    batch_operations, configs, control_jobs, cors, lifecycle, logging, notification, object_lock,
    replication, tagging,
};

/// A body as s3s reads an operation's XML: one root element, nothing after it.
fn xml<T: for<'x> Deserialize<'x>>(body: &[u8]) -> Option<T> {
    let mut d = Deserializer::new(body);
    let value = T::deserialize(&mut d).ok()?;
    d.expect_eof().ok()?;
    Some(value)
}

/// A bucket configuration's body, parsed and checked as its `Put…` operation does. The
/// first byte picks the configuration.
pub fn bucket_config_xml(data: &[u8]) {
    let Some((&which, body)) = data.split_first() else {
        return;
    };
    match which % 8 {
        0 => {
            if let Some(config) = xml::<dto::BucketLifecycleConfiguration>(body) {
                let _ = lifecycle::from_dto(Some(config), None);
            }
        }
        1 => {
            if let Some(config) = xml::<dto::CORSConfiguration>(body) {
                let _ = cors::from_dto(config);
            }
        }
        2 => {
            if let Ok(config) = replication::from_xml(body) {
                let _ = replication::checked(&config);
            }
        }
        3 => {
            if let Ok(pairs) = tagging::from_xml(body) {
                let _ = tagging::check(pairs, 50);
            }
        }
        4 => {
            if let Some(config) = xml::<dto::ObjectLockConfiguration>(body) {
                let _ = object_lock::config_from_dto(Some(config));
            }
        }
        5 => {
            if let Some(config) = xml::<dto::InventoryConfiguration>(body) {
                let _ = configs::inventory_from_dto(config);
            }
        }
        6 => {
            if let Some(status) = xml::<dto::BucketLoggingStatus>(body) {
                let _ = logging::from_dto(status);
            }
        }
        _ => {
            if let Some(config) = xml::<dto::NotificationConfiguration>(body) {
                let _ = notification::from_dto(config, TargetArn::parse, true);
            }
        }
    }
}

/// An S3 Control `CreateJobRequest` body, read and checked as `CreateJob` does.
pub fn create_job_xml(data: &[u8]) {
    control_jobs::job_of_body(data);
}

/// A piece of a CSV manifest, split into lines and each line into a task. The first
/// byte picks the manifest's fields.
pub fn manifest_csv(data: &[u8]) {
    let Some((&which, piece)) = data.split_first() else {
        return;
    };
    let fields: &[ManifestField] = match which % 4 {
        0 => &[ManifestField::Bucket, ManifestField::Key],
        1 => &[
            ManifestField::Bucket,
            ManifestField::Key,
            ManifestField::VersionId,
        ],
        2 => &[
            ManifestField::Ignore,
            ManifestField::Key,
            ManifestField::Bucket,
        ],
        _ => &[ManifestField::Key],
    };
    batch_operations::tasks_of(piece, fields);
}
