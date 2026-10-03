//! What an inventory report holds: a row of typed values per object or version, in
//! S3's columns, and how CSV writes them (every value quoted, the key URL-encoded, no
//! header).

use base64::{Engine, engine::general_purpose::STANDARD};
use teifs_store::{OWNER_ID, ObjectVersion};
use teifs_types::{
    Acl, Grantee, SseMode,
    configs::{InventoryConfig, InventoryField, InventoryFormat},
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

/// What a column holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Text,
    Bool,
    /// A 64-bit integer.
    Int,
    /// A time, in milliseconds since the Unix epoch.
    Time,
}

/// One column of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Column {
    /// S3's name for it in CSV (`LastModifiedDate`); ORC and Parquet use it in snake case.
    pub name: &'static str,
    pub kind: Kind,
    /// Always has a value (the bucket and the key).
    pub required: bool,
}

impl Column {
    const fn new(name: &'static str, kind: Kind) -> Self {
        Self {
            name,
            kind,
            required: false,
        }
    }

    /// Its name in ORC and Parquet: `last_modified_date`, `e_tag`.
    pub(crate) fn snake_name(&self) -> String {
        let mut out = String::new();
        for (i, c) in self.name.chars().enumerate() {
            if c.is_ascii_uppercase() && i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        }
        out
    }
}

/// One value of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Text(String),
    Bool(bool),
    Int(i64),
    Time(i64),
    /// Doesn't apply (most fields of a delete marker): empty in CSV, null in ORC and
    /// Parquet.
    None,
}

impl Value {
    /// Its size, roughly, for when to close a data file.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::None => 1,
            Self::Bool(_) | Self::Int(_) | Self::Time(_) => 8,
        }
    }
}

/// The columns of a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Schema {
    /// The files' format.
    pub format: InventoryFormat,
    /// Every version (with `VersionId`, `IsLatest` and `IsDeleteMarker`), or only the
    /// current ones.
    pub versions: bool,
    /// The optional fields, in S3's order.
    pub fields: Vec<InventoryField>,
}

impl Schema {
    pub(crate) fn of(config: &InventoryConfig) -> Self {
        Self {
            format: config.destination.format,
            versions: config.all_versions,
            fields: ORDER
                .into_iter()
                .filter(|field| config.fields.contains(field))
                .collect(),
        }
    }

    /// Its columns, in order.
    pub(crate) fn columns(&self) -> Vec<Column> {
        let mut columns = vec![
            Column {
                required: true,
                ..Column::new("Bucket", Kind::Text)
            },
            Column {
                required: true,
                ..Column::new("Key", Kind::Text)
            },
        ];
        if self.versions {
            columns.extend([
                Column::new("VersionId", Kind::Text),
                Column::new("IsLatest", Kind::Bool),
                Column::new("IsDeleteMarker", Kind::Bool),
            ]);
        }
        columns.extend(
            self.fields
                .iter()
                .map(|field| Column::new(field.name(), kind(*field))),
        );
        columns
    }

    /// The manifest's `fileSchema`, as S3 writes it for the format: the CSV columns'
    /// names, ORC's `struct<…>` or Parquet's message type.
    pub(crate) fn file_schema(&self) -> String {
        let columns = self.columns();
        match self.format {
            InventoryFormat::Csv => columns
                .iter()
                .map(|c| c.name)
                .collect::<Vec<_>>()
                .join(", "),
            InventoryFormat::Orc => {
                let fields: Vec<String> = columns
                    .iter()
                    .map(|c| {
                        let kind = match c.kind {
                            Kind::Text => "string",
                            Kind::Bool => "boolean",
                            Kind::Int => "bigint",
                            Kind::Time => "timestamp",
                        };
                        format!("{}:{kind}", c.snake_name())
                    })
                    .collect();
                format!("struct<{}>", fields.join(","))
            }
            InventoryFormat::Parquet => {
                let fields: Vec<String> = columns
                    .iter()
                    .map(|c| {
                        let repetition = if c.required { "required" } else { "optional" };
                        let kind = match c.kind {
                            Kind::Text => "binary",
                            Kind::Bool => "boolean",
                            Kind::Int | Kind::Time => "int64",
                        };
                        let annotation = match c.kind {
                            Kind::Text => " (UTF8)",
                            Kind::Time => " (TIMESTAMP_MILLIS)",
                            Kind::Bool | Kind::Int => "",
                        };
                        format!("{repetition} {kind} {}{annotation};", c.snake_name())
                    })
                    .collect();
                format!("message s3.inventory {{ {}}}", fields.join(" "))
            }
        }
    }

    /// Whether the rows need each object's lifecycle expiry.
    pub(crate) fn needs_expiry(&self) -> bool {
        self.fields
            .contains(&InventoryField::LifecycleExpirationDate)
    }

    /// `entry`'s row, a value for each column.
    pub(crate) fn row(&self, bucket: &str, entry: &Entry<'_>) -> Vec<Value> {
        let info = &entry.version.info;
        let mut values = vec![
            Value::Text(bucket.to_owned()),
            Value::Text(info.key.clone()),
        ];
        if self.versions {
            let version_id = info.version_id.as_deref().filter(|id| *id != "null");
            values.extend([
                version_id.map_or(Value::None, |id| Value::Text(id.to_owned())),
                Value::Bool(entry.version.latest),
                Value::Bool(entry.version.delete_marker),
            ]);
        }
        values.extend(self.fields.iter().map(|field| value(*field, entry)));
        values
    }
}

/// What a field holds.
fn kind(field: InventoryField) -> Kind {
    use InventoryField as F;
    match field {
        F::Size => Kind::Int,
        F::LastModifiedDate | F::ObjectLockRetainUntilDate | F::LifecycleExpirationDate => {
            Kind::Time
        }
        F::IsMultipartUploaded => Kind::Bool,
        _ => Kind::Text,
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

/// Appends a row as CSV to `out`, ending in a newline.
pub(crate) fn csv(row: &[Value], out: &mut String) {
    for (i, value) in row.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let text = match value {
            // The key, URL-encoded.
            Value::Text(key) if i == 1 => crate::encode::url(key),
            Value::Text(text) => text.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Time(ms) => iso(*ms),
            Value::None => String::new(),
        };
        out.push('"');
        out.push_str(&text.replace('"', "\"\""));
        out.push('"');
    }
    out.push('\n');
}

/// One field's value; none when it doesn't apply (most fields of a delete marker).
fn value(field: InventoryField, entry: &Entry<'_>) -> Value {
    use InventoryField as F;
    let info = &entry.version.info;
    let text = |text: &str| Value::Text(text.to_owned());
    match field {
        F::LastModifiedDate => return Value::Time(millis(info.modified)),
        F::ObjectOwner => return text(OWNER_ID),
        _ if entry.version.delete_marker => return Value::None,
        _ => {}
    }
    let retention = info.attrs.retention.as_ref();
    match field {
        F::Size => Value::Int(i64::try_from(info.size).unwrap_or(i64::MAX)),
        F::ETag => text(&info.etag),
        F::StorageClass => text("STANDARD"),
        F::IsMultipartUploaded => Value::Bool(!info.parts.is_empty()),
        F::EncryptionStatus => text(match info.sse.as_ref().map(|sse| sse.mode) {
            None => "NOT-SSE",
            Some(SseMode::S3) => "SSE-S3",
            Some(SseMode::Kms) => "SSE-KMS",
            Some(SseMode::Dsse) => "DSSE-KMS",
            Some(SseMode::Customer) => "SSE-C",
        }),
        F::ObjectLockRetainUntilDate => retention.map_or(Value::None, |r| Value::Time(r.until_ms)),
        F::ObjectLockMode => retention.map_or(Value::None, |r| text(r.mode.as_str())),
        F::ObjectLockLegalHoldStatus => match info.attrs.legal_hold {
            Some(true) => text("ON"),
            _ if entry.locked => text("OFF"),
            _ => Value::None,
        },
        F::BucketKeyStatus => text(if info.sse.as_ref().is_some_and(|sse| sse.bucket_key) {
            "ENABLED"
        } else {
            "DISABLED"
        }),
        F::ChecksumAlgorithm => checksum_algorithm(&info.attrs.checksums).map_or(Value::None, text),
        F::ObjectAccessControlList => Value::Text(acl_json(info.attrs.acl.as_ref())),
        F::LifecycleExpirationDate => entry.expiry_ms.map_or(Value::None, Value::Time),
        F::ReplicationStatus => info
            .attrs
            .replication
            .as_ref()
            .map_or(Value::None, |r| text(r.status.as_str())),
        // Not kept by TeiFS: every object is STANDARD, and Object Lock has no event holds.
        F::IntelligentTieringAccessTier
        | F::ObjectLockEventHoldStatus
        | F::ObjectLockEventHoldDuration
        | F::LastModifiedDate
        | F::ObjectOwner => Value::None,
    }
}

/// The algorithm of the object's checksum: the one asked for, when it has S3's default
/// besides.
fn checksum_algorithm(checksums: &std::collections::BTreeMap<String, String>) -> Option<&str> {
    checksums
        .keys()
        .find(|algorithm| *algorithm != checksums::DEFAULT_ALGORITHM)
        .or_else(|| checksums.keys().next())
        .map(String::as_str)
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use teifs_types::{
        AclGrant, LockMode, ObjectAttrs, ObjectInfo, PartInfo, Permission, Retention, SseInfo,
        configs::{Frequency, InventoryDestination},
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
        csv(&schema.row("photos", entry), &mut out);
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
            schema.file_schema(),
            "Bucket, Key, VersionId, IsLatest, IsDeleteMarker, Size, ETag, ObjectOwner"
        );
        assert!(!schema.needs_expiry());
        let current = Schema::of(&config(
            false,
            vec![InventoryField::LifecycleExpirationDate],
        ));
        assert_eq!(
            current.file_schema(),
            "Bucket, Key, LifecycleExpirationDate"
        );
        assert!(current.needs_expiry());
        assert_eq!(ORDER.len(), InventoryField::ALL.len());
        assert!(InventoryField::ALL.iter().all(|f| ORDER.contains(f)));
    }

    #[test]
    fn file_schemas_are_s3s() {
        let mut schema = Schema::of(&config(
            true,
            vec![
                InventoryField::ETag,
                InventoryField::Size,
                InventoryField::LastModifiedDate,
            ],
        ));
        schema.format = InventoryFormat::Orc;
        assert_eq!(
            schema.file_schema(),
            "struct<bucket:string,key:string,version_id:string,is_latest:boolean,\
             is_delete_marker:boolean,size:bigint,last_modified_date:timestamp,e_tag:string>"
        );
        schema.format = InventoryFormat::Parquet;
        assert_eq!(
            schema.file_schema(),
            "message s3.inventory { required binary bucket (UTF8); required binary key (UTF8); \
             optional binary version_id (UTF8); optional boolean is_latest; optional boolean \
             is_delete_marker; optional int64 size; optional int64 last_modified_date \
             (TIMESTAMP_MILLIS); optional binary e_tag (UTF8);}"
        );
        // Every field, as AWS's example names the ones it shows.
        let mut every = Schema::of(&config(true, InventoryField::ALL.to_vec()));
        every.format = InventoryFormat::Orc;
        assert!(every.file_schema().starts_with(
            "struct<bucket:string,key:string,version_id:string,is_latest:boolean,\
             is_delete_marker:boolean,size:bigint,last_modified_date:timestamp,e_tag:string,\
             storage_class:string,is_multipart_uploaded:boolean,replication_status:string,\
             encryption_status:string,object_lock_retain_until_date:timestamp,\
             object_lock_mode:string,object_lock_legal_hold_status:string,\
             intelligent_tiering_access_tier:string,bucket_key_status:string,\
             checksum_algorithm:string,object_access_control_list:string,object_owner:string,\
             lifecycle_expiration_date:timestamp,"
        ));
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
    fn replication_status_is_the_versions() {
        let schema = Schema::of(&config(false, vec![InventoryField::ReplicationStatus]));
        let mut object = version("k");
        let row_of = |object: &ObjectVersion| {
            line(
                &schema,
                &Entry {
                    version: object,
                    expiry_ms: None,
                    locked: false,
                },
            )
        };
        assert_eq!(row_of(&object), "\"photos\",\"k\",\"\"\n");
        object.info.attrs.replication =
            Some(teifs_types::replication::VersionReplication::replica());
        assert_eq!(row_of(&object), "\"photos\",\"k\",\"REPLICA\"\n");
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
}
