//! Server access logging: where a bucket's access log records go, as S3's
//! `PutBucketLogging` sets it.

use serde::{Deserialize, Serialize};

use crate::AclGrant;

/// The service principal access logs are delivered as, which a target bucket's policy
/// names to let them in.
pub const SERVICE: &str = "logging.s3.amazonaws.com";

/// A bucket's access logging: its records are delivered as objects to another bucket
/// (or itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingConfig {
    /// The bucket the log objects go to.
    pub target_bucket: String,
    /// What every log object's key starts with (may be empty).
    pub target_prefix: String,
    /// How log objects are named, when the configuration said (`None`: the simple
    /// format, and `GetBucketLogging` answers without one, as it was given).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_format: Option<KeyFormat>,
    /// Who else may reach the log objects (`TargetGrants`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<AclGrant>,
}

/// How log objects are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyFormat {
    /// `PREFIX` + `YYYY-MM-DD-hh-mm-ss-UNIQUE` (`SimplePrefix`).
    Simple,
    /// `PREFIX` + `ACCOUNT/REGION/BUCKET/YYYY/MM/DD/` + the simple name
    /// (`PartitionedPrefix`); the date source when the configuration gave one.
    Partitioned(Option<DateSource>),
}

/// Which time a partitioned key's date is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DateSource {
    /// The day the records' requests were made, time 00:00:00 (S3's default).
    EventTime,
    /// When the log object was delivered.
    DeliveryTime,
}

impl DateSource {
    /// S3's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EventTime => "EventTime",
            Self::DeliveryTime => "DeliveryTime",
        }
    }

    /// The source S3's name names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::EventTime, Self::DeliveryTime]
            .into_iter()
            .find(|source| source.name() == name)
    }
}

impl LoggingConfig {
    /// The date source log object keys use: `None` for the simple format.
    #[must_use]
    pub fn date_source(&self) -> Option<DateSource> {
        match self.key_format? {
            KeyFormat::Simple => None,
            KeyFormat::Partitioned(source) => Some(source.unwrap_or(DateSource::EventTime)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Grantee, Permission};

    #[test]
    fn configurations_round_trip_as_given() {
        let config = LoggingConfig {
            target_bucket: "logs".to_owned(),
            target_prefix: "src/".to_owned(),
            key_format: Some(KeyFormat::Partitioned(None)),
            grants: vec![AclGrant {
                grantee: Grantee::AllUsers,
                permission: Permission::Read,
            }],
        };
        let text = serde_json::to_string(&config).unwrap();
        assert_eq!(
            text,
            r#"{"targetBucket":"logs","targetPrefix":"src/","keyFormat":{"partitioned":null},"grants":[{"grantee":"allUsers","permission":"READ"}]}"#
        );
        assert_eq!(
            serde_json::from_str::<LoggingConfig>(&text).unwrap(),
            config
        );
        let bare: LoggingConfig =
            serde_json::from_str(r#"{"targetBucket":"logs","targetPrefix":""}"#).unwrap();
        assert_eq!(bare.key_format, None);
        assert!(bare.grants.is_empty());
    }

    #[test]
    fn partitioned_keys_default_to_the_event_time() {
        let mut config = LoggingConfig {
            target_bucket: "logs".to_owned(),
            target_prefix: String::new(),
            key_format: None,
            grants: Vec::new(),
        };
        assert_eq!(config.date_source(), None);
        config.key_format = Some(KeyFormat::Simple);
        assert_eq!(config.date_source(), None);
        config.key_format = Some(KeyFormat::Partitioned(None));
        assert_eq!(config.date_source(), Some(DateSource::EventTime));
        config.key_format = Some(KeyFormat::Partitioned(Some(DateSource::DeliveryTime)));
        assert_eq!(config.date_source(), Some(DateSource::DeliveryTime));
        for source in [DateSource::EventTime, DateSource::DeliveryTime] {
            assert_eq!(DateSource::parse(source.name()), Some(source));
        }
        assert_eq!(DateSource::parse("eventtime"), None);
    }
}
