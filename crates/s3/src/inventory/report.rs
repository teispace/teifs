//! What an inventory report holds: a row per object or version, as S3 writes it in CSV
//! (every value quoted, the key URL-encoded, no header), and the gzipped data files the
//! rows go into.

use std::io::{self, Write};

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use teifs_store::{OWNER_ID, ObjectVersion};
use teifs_types::{
    Acl, Grantee, SseMode,
    configs::{InventoryConfig, InventoryField},
};

use crate::checksums;

/// The optional fields in the order S3 writes them (its `fileSchema`'s), whatever order
/// the configuration names them in.
const ORDER: [InventoryField; 18] = {
    use InventoryField as F;
    [
        F::Size,
        F::LastModifiedDate,
        F::ETag,
        F::StorageClass,
        F::IsMultipartUploaded,
        F::ReplicationStatus,
        F::EncryptionStatus,
        F::ObjectLockRetainUntilDate,
        F::ObjectLockMode,
        F::ObjectLockLegalHoldStatus,
        F::IntelligentTieringAccessTier,
        F::BucketKeyStatus,
        F::ChecksumAlgorithm,
        F::ObjectAccessControlList,
        F::ObjectOwner,
        F::LifecycleExpirationDate,
        F::ObjectLockEventHoldStatus,
        F::ObjectLockEventHoldDuration,
    ]
};

/// The columns of a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Schema {
    /// Every version (with `VersionId`, `IsLatest` and `IsDeleteMarker`), or only the
    /// current ones.
    pub versions: bool,
    /// The optional fields, in S3's order.
    pub fields: Vec<InventoryField>,
}

impl Schema {
    pub(crate) fn of(config: &InventoryConfig) -> Self {
        Self {
            versions: config.all_versions,
            fields: ORDER
                .into_iter()
                .filter(|field| config.fields.contains(field))
                .collect(),
        }
    }

    /// The manifest's `fileSchema`: the columns' names, comma separated.
    pub(crate) fn names(&self) -> String {
        let fixed: &[&str] = if self.versions {
            &["Bucket", "Key", "VersionId", "IsLatest", "IsDeleteMarker"]
        } else {
            &["Bucket", "Key"]
        };
        fixed
            .iter()
            .copied()
            .chain(self.fields.iter().map(|field| field.name()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether the rows need each object's lifecycle expiry.
    pub(crate) fn needs_expiry(&self) -> bool {
        self.fields
            .contains(&InventoryField::LifecycleExpirationDate)
    }
}

/// One object or version, with what its row needs besides.
#[derive(Debug)]
pub(crate) struct Entry<'a> {
    pub version: &'a ObjectVersion,
    /// When the lifecycle expires it, in milliseconds since the Unix epoch.
    pub expiry_ms: Option<i64>,
    /// Whether the bucket has Object Lock (so a version without a legal hold is `OFF`).
    pub locked: bool,
}

/// Appends `entry`'s CSV row to `out`, ending in a newline.
pub(crate) fn row(schema: &Schema, bucket: &str, entry: &Entry<'_>, out: &mut String) {
    let info = &entry.version.info;
    let mut values = vec![bucket.to_owned(), crate::encode::url(&info.key)];
    if schema.versions {
        let version_id = info
            .version_id
            .as_deref()
            .filter(|id| *id != "null")
            .unwrap_or_default();
        values.extend([
            version_id.to_owned(),
            entry.version.latest.to_string(),
            entry.version.delete_marker.to_string(),
        ]);
    }
    values.extend(schema.fields.iter().map(|field| value(*field, entry)));
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&value.replace('"', "\"\""));
        out.push('"');
    }
    out.push('\n');
}

/// One field's value; empty when it doesn't apply (most fields of a delete marker).
fn value(field: InventoryField, entry: &Entry<'_>) -> String {
    use InventoryField as F;
    let info = &entry.version.info;
    match field {
        F::LastModifiedDate => return iso(millis(info.modified)),
        F::ObjectOwner => return OWNER_ID.to_owned(),
        _ if entry.version.delete_marker => return String::new(),
        _ => {}
    }
    let retention = info.attrs.retention.as_ref();
    match field {
        F::Size => info.size.to_string(),
        F::ETag => info.etag.clone(),
        F::StorageClass => "STANDARD".to_owned(),
        F::IsMultipartUploaded => (!info.parts.is_empty()).to_string(),
        F::EncryptionStatus => match info.sse.as_ref().map(|sse| sse.mode) {
            None => "NOT-SSE",
            Some(SseMode::S3) => "SSE-S3",
            Some(SseMode::Kms) => "SSE-KMS",
            Some(SseMode::Dsse) => "DSSE-KMS",
            Some(SseMode::Customer) => "SSE-C",
        }
        .to_owned(),
        F::ObjectLockRetainUntilDate => retention.map(|r| iso(r.until_ms)).unwrap_or_default(),
        F::ObjectLockMode => retention
            .map(|r| r.mode.as_str().to_owned())
            .unwrap_or_default(),
        F::ObjectLockLegalHoldStatus => match info.attrs.legal_hold {
            Some(true) => "ON".to_owned(),
            _ if entry.locked => "OFF".to_owned(),
            _ => String::new(),
        },
        F::BucketKeyStatus => if info.sse.as_ref().is_some_and(|sse| sse.bucket_key) {
            "ENABLED"
        } else {
            "DISABLED"
        }
        .to_owned(),
        F::ChecksumAlgorithm => checksum_algorithm(&info.attrs.checksums),
        F::ObjectAccessControlList => acl_json(info.attrs.acl.as_ref()),
        F::LifecycleExpirationDate => entry.expiry_ms.map(iso).unwrap_or_default(),
        // Not kept by TeiFS: no replication yet, every object is STANDARD, and Object
        // Lock has no event holds.
        F::ReplicationStatus
        | F::IntelligentTieringAccessTier
        | F::ObjectLockEventHoldStatus
        | F::ObjectLockEventHoldDuration
        | F::LastModifiedDate
        | F::ObjectOwner => String::new(),
    }
}

/// The algorithm of the object's checksum: the one asked for, when it has S3's default
/// besides.
fn checksum_algorithm(checksums: &std::collections::BTreeMap<String, String>) -> String {
    checksums
        .keys()
        .find(|algorithm| *algorithm != checksums::DEFAULT_ALGORITHM)
        .or_else(|| checksums.keys().next())
        .cloned()
        .unwrap_or_default()
}

/// The object's ACL as S3's inventory gives it: base64 of a JSON document with its
/// grants.
fn acl_json(acl: Option<&Acl>) -> String {
    let private = Acl::private();
    let grants: Vec<serde_json::Value> = acl
        .unwrap_or(&private)
        .grants
        .iter()
        .map(|grant| match grant.grantee.uri() {
            Some(uri) => serde_json::json!({
                "uri": uri,
                "type": "Group",
                "permission": grant.permission.name(),
            }),
            None => serde_json::json!({
                "canonicalId": OWNER_ID,
                "type": "CanonicalUser",
                "permission": grant.permission.name(),
            }),
        })
        .collect();
    debug_assert!(Grantee::Owner.uri().is_none());
    let document = serde_json::json!({
        "version": "2022-11-10",
        "status": "AVAILABLE",
        "grants": grants,
    });
    STANDARD.encode(document.to_string())
}

/// Milliseconds since the Unix epoch.
fn millis(time: std::time::SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// A time as S3's inventory writes it: `2024-08-21T15:28:26.000Z`.
pub(crate) fn iso(ms: i64) -> String {
    let time = time::OffsetDateTime::UNIX_EPOCH + time::Duration::milliseconds(ms);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond()
    )
}

/// The gzipped data files a report's rows go into, each closed once it's `roll_at`
/// bytes.
pub(crate) struct DataFiles {
    roll_at: usize,
    file: Option<GzEncoder<Vec<u8>>>,
}

impl DataFiles {
    pub(crate) fn new(roll_at: usize) -> Self {
        Self {
            roll_at,
            file: None,
        }
    }

    /// Adds rows; returns a file when it's full.
    pub(crate) fn push(&mut self, rows: &str) -> io::Result<Option<Vec<u8>>> {
        let file = self
            .file
            .get_or_insert_with(|| GzEncoder::new(Vec::new(), Compression::default()));
        file.write_all(rows.as_bytes())?;
        if file.get_ref().len() >= self.roll_at {
            return self.finish();
        }
        Ok(None)
    }

    /// The last file, if rows were added since the last one.
    pub(crate) fn finish(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.file.take().map(GzEncoder::finish).transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Read,
        time::{Duration, UNIX_EPOCH},
    };

    use flate2::read::GzDecoder;
    use teifs_types::{
        AclGrant, LockMode, ObjectAttrs, ObjectInfo, PartInfo, Permission, Retention, SseInfo,
        configs::{Frequency, InventoryDestination, InventoryFormat},
    };

    use super::*;

    fn config(all_versions: bool, fields: Vec<InventoryField>) -> InventoryConfig {
        InventoryConfig {
            enabled: true,
            prefix: None,
            destination: InventoryDestination {
                bucket: "reports".to_owned(),
                account: None,
                format: InventoryFormat::Csv,
                prefix: None,
                encryption: None,
            },
            all_versions,
            fields,
            frequency: Frequency::Daily,
        }
    }

    fn version(key: &str) -> ObjectVersion {
        ObjectVersion {
            info: ObjectInfo {
                key: key.to_owned(),
                size: 5,
                modified: UNIX_EPOCH + Duration::from_millis(1_724_254_106_123),
                etag: "abc".to_owned(),
                attrs: ObjectAttrs::default(),
                sse: None,
                parts: Vec::new(),
                version_id: Some("v1".to_owned()),
            },
            latest: true,
            delete_marker: false,
        }
    }

    fn line(schema: &Schema, entry: &Entry<'_>) -> String {
        let mut out = String::new();
        row(schema, "photos", entry, &mut out);
        out
    }

    #[test]
    fn fields_follow_s3s_order_whatever_the_configurations() {
        let schema = Schema::of(&config(
            true,
            vec![
                InventoryField::ObjectOwner,
                InventoryField::Size,
                InventoryField::ETag,
            ],
        ));
        assert_eq!(
            schema.names(),
            "Bucket, Key, VersionId, IsLatest, IsDeleteMarker, Size, ETag, ObjectOwner"
        );
        assert!(!schema.needs_expiry());
        let current = Schema::of(&config(
            false,
            vec![InventoryField::LifecycleExpirationDate],
        ));
        assert_eq!(current.names(), "Bucket, Key, LifecycleExpirationDate");
        assert!(current.needs_expiry());
        assert_eq!(ORDER.len(), InventoryField::ALL.len());
        assert!(InventoryField::ALL.iter().all(|f| ORDER.contains(f)));
    }

    #[test]
    fn a_row_quotes_every_value_and_encodes_the_key() {
        let schema = Schema::of(&config(true, vec![InventoryField::Size]));
        let mut quoted = version("a \"b\"/c+d.txt");
        quoted.info.version_id = Some("null".to_owned());
        let entry = Entry {
            version: &quoted,
            expiry_ms: None,
            locked: false,
        };
        assert_eq!(
            line(&schema, &entry),
            "\"photos\",\"a%20%22b%22/c%2Bd.txt\",\"\",\"true\",\"false\",\"5\"\n"
        );
        let current = Schema::of(&config(false, vec![]));
        let plain = version("k");
        let entry = Entry {
            version: &plain,
            expiry_ms: None,
            locked: false,
        };
        assert_eq!(line(&current, &entry), "\"photos\",\"k\"\n");
    }

    #[test]
    fn every_field_says_what_s3_would() {
        let schema = Schema::of(&config(false, InventoryField::ALL.to_vec()));
        let mut object = version("k");
        object.info.parts = vec![PartInfo::default()];
        object.info.sse = Some(SseInfo {
            mode: SseMode::Kms,
            kms_key: Some("key".to_owned()),
            customer_key_md5: None,
            bucket_key: true,
        });
        object.info.attrs.checksums = [("CRC64NVME", "x"), ("SHA256", "y")]
            .map(|(a, v)| (a.to_owned(), v.to_owned()))
            .into();
        object.info.attrs.retention = Some(Retention {
            mode: LockMode::Governance,
            until_ms: 1_800_000_000_000,
        });
        object.info.attrs.legal_hold = Some(true);
        let entry = Entry {
            version: &object,
            expiry_ms: Some(1_900_000_000_000),
            locked: true,
        };
        let private = acl_json(None);
        assert_eq!(
            line(&schema, &entry),
            format!(
                "\"photos\",\"k\",\"5\",\"2024-08-21T15:28:26.123Z\",\"abc\",\"STANDARD\",\"true\",\"\",\
                 \"SSE-KMS\",\"2027-01-15T08:00:00.000Z\",\"GOVERNANCE\",\"ON\",\"\",\"ENABLED\",\
                 \"SHA256\",\"{private}\",\"teifs\",\"2030-03-17T17:46:40.000Z\",\"\",\"\"\n"
            )
        );
    }

    #[test]
    fn a_delete_marker_has_only_its_date_and_owner() {
        let schema = Schema::of(&config(true, InventoryField::ALL.to_vec()));
        let mut marker = version("k");
        marker.latest = false;
        marker.delete_marker = true;
        let entry = Entry {
            version: &marker,
            expiry_ms: Some(1),
            locked: true,
        };
        let mut want = String::from(
            "\"photos\",\"k\",\"v1\",\"false\",\"true\",\"\",\"2024-08-21T15:28:26.123Z\"",
        );
        for field in &ORDER[2..] {
            want.push_str(if *field == InventoryField::ObjectOwner {
                ",\"teifs\""
            } else {
                ",\"\""
            });
        }
        want.push('\n');
        assert_eq!(line(&schema, &entry), want);
    }

    #[test]
    fn legal_holds_and_encryption_read_as_s3s() {
        let schema = Schema::of(&config(
            false,
            vec![
                InventoryField::ObjectLockLegalHoldStatus,
                InventoryField::EncryptionStatus,
                InventoryField::BucketKeyStatus,
                InventoryField::ChecksumAlgorithm,
            ],
        ));
        let mut object = version("k");
        object.info.attrs.checksums = [("CRC64NVME".to_owned(), "x".to_owned())].into();
        let row_of = |object: &ObjectVersion, locked| {
            line(
                &schema,
                &Entry {
                    version: object,
                    expiry_ms: None,
                    locked,
                },
            )
        };
        assert_eq!(
            row_of(&object, false),
            "\"photos\",\"k\",\"NOT-SSE\",\"\",\"DISABLED\",\"CRC64NVME\"\n"
        );
        object.info.attrs.legal_hold = Some(false);
        assert!(row_of(&object, true).contains(",\"OFF\","));
        for (mode, name) in [
            (SseMode::S3, "SSE-S3"),
            (SseMode::Dsse, "DSSE-KMS"),
            (SseMode::Customer, "SSE-C"),
        ] {
            object.info.sse = Some(SseInfo {
                mode,
                kms_key: None,
                customer_key_md5: None,
                bucket_key: false,
            });
            assert!(row_of(&object, false).contains(&format!(",\"{name}\",")));
        }
    }

    #[test]
    fn an_acl_is_base64_json_of_its_grants() {
        let acl = Acl {
            grants: vec![
                AclGrant {
                    grantee: Grantee::Owner,
                    permission: Permission::FullControl,
                },
                AclGrant {
                    grantee: Grantee::AllUsers,
                    permission: Permission::Read,
                },
            ],
        };
        let json: serde_json::Value =
            serde_json::from_slice(&STANDARD.decode(acl_json(Some(&acl))).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": "2022-11-10",
                "status": "AVAILABLE",
                "grants": [
                    {"canonicalId": "teifs", "type": "CanonicalUser", "permission": "FULL_CONTROL"},
                    {"uri": "http://acs.amazonaws.com/groups/global/AllUsers", "type": "Group", "permission": "READ"},
                ],
            })
        );
    }

    #[test]
    fn data_files_roll_when_full() {
        let gunzip = |file: &[u8]| {
            let mut text = String::new();
            GzDecoder::new(file).read_to_string(&mut text).unwrap();
            text
        };
        let mut files = DataFiles::new(1);
        let first = files.push("a\n").unwrap().unwrap();
        assert_eq!(gunzip(&first), "a\n");
        assert!(files.finish().unwrap().is_none());
        let mut files = DataFiles::new(1 << 20);
        assert!(files.push("a\n").unwrap().is_none());
        assert!(files.push("b\n").unwrap().is_none());
        assert_eq!(gunzip(&files.finish().unwrap().unwrap()), "a\nb\n");
        // A file closes once it's exactly as big as asked.
        let mut files = DataFiles::new(10);
        assert!(
            files.push("a").unwrap().is_some(),
            "the gzip header alone is 10 bytes"
        );
        assert!(files.finish().unwrap().is_none());
    }
}
