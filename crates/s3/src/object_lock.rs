//! S3 Object Lock's messages: a bucket's lock configuration, a version's retention and
//! legal hold, and the `x-amz-object-lock-*` headers of writes and reads. The rules
//! themselves are the store's.

use s3s::{S3Error, S3ErrorCode, S3Result, dto, s3_error};
use teifs_store::{
    DefaultRetention, LockMode, ObjectAttrs, ObjectLock, Retention, RetentionPeriod,
};

/// A time as S3 sends it, in milliseconds since the Unix epoch.
pub(crate) fn ms_of(timestamp: &dto::Timestamp) -> i64 {
    let time = time::OffsetDateTime::from(timestamp.clone());
    i64::try_from(time.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

fn now_ms() -> i64 {
    ms_of(&dto::Timestamp::from(std::time::SystemTime::now()))
}

/// A lock mode S3 names exactly (upper case); anything else is malformed.
fn mode(name: &str) -> S3Result<LockMode> {
    LockMode::parse(name).ok_or_else(|| s3_error!(MalformedXML))
}

/// A bucket's Object Lock from `PutObjectLockConfiguration`'s body.
pub(crate) fn config_from_dto(
    config: Option<dto::ObjectLockConfiguration>,
) -> S3Result<ObjectLock> {
    let config = config.ok_or_else(|| s3_error!(MalformedXML))?;
    if config
        .object_lock_enabled
        .as_ref()
        .map(dto::ObjectLockEnabled::as_str)
        != Some(dto::ObjectLockEnabled::ENABLED)
    {
        return Err(s3_error!(MalformedXML));
    }
    let Some(retention) = config.rule.and_then(|rule| rule.default_retention) else {
        return Ok(ObjectLock::default());
    };
    let mode = mode(
        retention
            .mode
            .as_ref()
            .ok_or_else(|| s3_error!(MalformedXML))?
            .as_str(),
    )?;
    let period = match (retention.days, retention.years) {
        (Some(days), None) => RetentionPeriod::Days(u32::try_from(days).unwrap_or(0)),
        (None, Some(years)) => RetentionPeriod::Years(u32::try_from(years).unwrap_or(0)),
        _ => return Err(s3_error!(MalformedXML)),
    };
    if !period.is_valid() {
        let mut err = S3Error::with_message(
            S3ErrorCode::Custom("InvalidRetentionPeriod".into()),
            "Default retention period must be a positive integer value, of at most 100 years.",
        );
        err.set_status_code(http::StatusCode::BAD_REQUEST);
        return Err(err);
    }
    Ok(ObjectLock {
        default_retention: Some(DefaultRetention { mode, period }),
    })
}

/// A bucket's Object Lock as `GetObjectLockConfiguration` answers it.
pub(crate) fn config_to_dto(lock: &ObjectLock) -> dto::ObjectLockConfiguration {
    dto::ObjectLockConfiguration {
        object_lock_enabled: Some(dto::ObjectLockEnabled::from_static(
            dto::ObjectLockEnabled::ENABLED,
        )),
        rule: lock.default_retention.map(|d| {
            let (days, years) = match d.period {
                RetentionPeriod::Days(days) => (i32::try_from(days).ok(), None),
                RetentionPeriod::Years(years) => (None, i32::try_from(years).ok()),
            };
            dto::ObjectLockRule {
                default_retention: Some(dto::DefaultRetention {
                    days,
                    years,
                    mode: Some(dto::ObjectLockRetentionMode::from_static(d.mode.as_str())),
                }),
            }
        }),
    }
}

/// A retention a date must end in the future, as S3 requires of a new one.
fn future(until: &dto::Timestamp) -> S3Result<i64> {
    let ms = ms_of(until);
    if ms <= now_ms() {
        return Err(s3_error!(
            InvalidArgument,
            "The retain until date must be in the future!"
        ));
    }
    Ok(ms)
}

/// A version's retention from `PutObjectRetention`'s body; an empty one removes it.
pub(crate) fn retention_from_dto(
    retention: Option<dto::ObjectLockRetention>,
) -> S3Result<Option<Retention>> {
    let Some(retention) = retention else {
        return Ok(None);
    };
    match (retention.mode, retention.retain_until_date) {
        (None, None) => Ok(None),
        (Some(m), Some(until)) => Ok(Some(Retention {
            mode: mode(m.as_str())?,
            until_ms: future(&until)?,
        })),
        _ => Err(s3_error!(MalformedXML)),
    }
}

/// A version's retention as `GetObjectRetention` answers it.
pub(crate) fn retention_to_dto(retention: &Retention) -> dto::ObjectLockRetention {
    dto::ObjectLockRetention {
        mode: Some(dto::ObjectLockRetentionMode::from_static(
            retention.mode.as_str(),
        )),
        retain_until_date: Some(crate::drive::millis(retention.until_ms)),
    }
}

/// A legal hold's status, `ON` or `OFF`.
fn hold(status: &str) -> Option<bool> {
    match status {
        dto::ObjectLockLegalHoldStatus::ON => Some(true),
        dto::ObjectLockLegalHoldStatus::OFF => Some(false),
        _ => None,
    }
}

/// A legal hold from `PutObjectLegalHold`'s body.
pub(crate) fn legal_hold_from_dto(legal_hold: Option<dto::ObjectLockLegalHold>) -> S3Result<bool> {
    legal_hold
        .and_then(|h| h.status)
        .and_then(|s| hold(s.as_str()))
        .ok_or_else(|| s3_error!(MalformedXML))
}

fn hold_status(on: bool) -> dto::ObjectLockLegalHoldStatus {
    dto::ObjectLockLegalHoldStatus::from_static(if on {
        dto::ObjectLockLegalHoldStatus::ON
    } else {
        dto::ObjectLockLegalHoldStatus::OFF
    })
}

/// A legal hold as `GetObjectLegalHold` answers it.
pub(crate) fn legal_hold_to_dto(on: bool) -> dto::ObjectLockLegalHold {
    dto::ObjectLockLegalHold {
        status: Some(hold_status(on)),
    }
}

/// The lock a write asks for with its `x-amz-object-lock-*` headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WriteLock {
    pub retention: Option<Retention>,
    pub legal_hold: Option<bool>,
}

impl WriteLock {
    /// Reads and checks the headers: a mode and a date come together, the date in the
    /// future; a legal hold is `ON` or `OFF`.
    pub(crate) fn from_headers(
        mode: Option<&dto::ObjectLockMode>,
        until: Option<&dto::Timestamp>,
        legal_hold: Option<&dto::ObjectLockLegalHoldStatus>,
    ) -> S3Result<Self> {
        let retention = match (mode, until) {
            (None, None) => None,
            (Some(m), Some(until)) => Some(Retention {
                mode: LockMode::parse(m.as_str())
                    .ok_or_else(|| s3_error!(InvalidArgument, "Unknown wormMode directive."))?,
                until_ms: future(until)?,
            }),
            _ => {
                return Err(s3_error!(
                    InvalidArgument,
                    "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied"
                ));
            }
        };
        let legal_hold = legal_hold
            .map(|s| {
                hold(s.as_str()).ok_or_else(|| {
                    s3_error!(
                        InvalidArgument,
                        "Legal Hold must be either of 'ON' or 'OFF'"
                    )
                })
            })
            .transpose()?;
        Ok(Self {
            retention,
            legal_hold,
        })
    }

    /// Whether it asks for anything.
    pub(crate) fn is_some(&self) -> bool {
        self.retention.is_some() || self.legal_hold.is_some()
    }

    /// Gives `attrs` this lock.
    pub(crate) fn apply(self, attrs: &mut ObjectAttrs) {
        attrs.retention = self.retention;
        attrs.legal_hold = self.legal_hold;
    }
}

/// Reads a write's lock headers from an input with S3's field names.
macro_rules! write_lock {
    ($input:expr) => {
        $crate::object_lock::WriteLock::from_headers(
            $input.object_lock_mode.as_ref(),
            $input.object_lock_retain_until_date.as_ref(),
            $input.object_lock_legal_hold_status.as_ref(),
        )
    };
}
pub(crate) use write_lock;

/// What a read shows of a version's lock: its retention to whoever may read retention,
/// its legal hold to whoever may read legal holds.
pub(crate) struct ReadLock {
    pub mode: Option<dto::ObjectLockMode>,
    pub until: Option<dto::Timestamp>,
    pub legal_hold: Option<dto::ObjectLockLegalHoldStatus>,
}

impl ReadLock {
    pub(crate) fn of(attrs: &ObjectAttrs, retention: bool, legal_hold: bool) -> Self {
        let shown = attrs.retention.filter(|_| retention);
        Self {
            mode: shown.map(|r| dto::ObjectLockMode::from_static(r.mode.as_str())),
            until: shown.map(|r| crate::drive::millis(r.until_ms)),
            legal_hold: attrs.legal_hold.filter(|_| legal_hold).map(hold_status),
        }
    }
}

/// Sets a read's `x-amz-object-lock-*` headers.
macro_rules! set_lock {
    ($out:expr, $lock:expr) => {{
        let lock: $crate::object_lock::ReadLock = $lock;
        $out.object_lock_mode = lock.mode;
        $out.object_lock_retain_until_date = lock.until;
        $out.object_lock_legal_hold_status = lock.legal_hold;
    }};
}
pub(crate) use set_lock;

#[cfg(test)]
mod tests {
    use super::*;

    fn config(
        enabled: &str,
        mode: Option<&str>,
        days: Option<i32>,
        years: Option<i32>,
    ) -> dto::ObjectLockConfiguration {
        dto::ObjectLockConfiguration {
            object_lock_enabled: Some(dto::ObjectLockEnabled::from(enabled.to_owned())),
            rule: mode.map(|mode| dto::ObjectLockRule {
                default_retention: Some(dto::DefaultRetention {
                    mode: Some(dto::ObjectLockRetentionMode::from(mode.to_owned())),
                    days,
                    years,
                }),
            }),
        }
    }

    fn code(err: &S3Error) -> &str {
        err.code().as_str()
    }

    #[test]
    fn a_lock_configuration_is_checked_as_s3_checks_it() {
        let lock =
            config_from_dto(Some(config("Enabled", Some("GOVERNANCE"), Some(1), None))).unwrap();
        assert_eq!(
            lock.default_retention,
            Some(DefaultRetention {
                mode: LockMode::Governance,
                period: RetentionPeriod::Days(1)
            })
        );
        let back = config_from_dto(Some(config_to_dto(&lock))).unwrap();
        assert_eq!(back, lock);
        let years =
            config_from_dto(Some(config("Enabled", Some("COMPLIANCE"), None, Some(2)))).unwrap();
        assert_eq!(config_from_dto(Some(config_to_dto(&years))).unwrap(), years);
        assert_eq!(
            config_from_dto(Some(config("Enabled", None, None, None))).unwrap(),
            ObjectLock::default()
        );
        assert!(config_to_dto(&ObjectLock::default()).rule.is_none());

        for (bad, expected) in [
            (
                config("Disabled", Some("GOVERNANCE"), Some(1), None),
                "MalformedXML",
            ),
            (
                config("Enabled", Some("governance"), Some(1), None),
                "MalformedXML",
            ),
            (
                config("Enabled", Some("abc"), Some(1), None),
                "MalformedXML",
            ),
            (
                config("Enabled", Some("GOVERNANCE"), Some(1), Some(1)),
                "MalformedXML",
            ),
            (
                config("Enabled", Some("GOVERNANCE"), None, None),
                "MalformedXML",
            ),
            (
                config("Enabled", Some("GOVERNANCE"), Some(0), None),
                "InvalidRetentionPeriod",
            ),
            (
                config("Enabled", Some("GOVERNANCE"), None, Some(-1)),
                "InvalidRetentionPeriod",
            ),
            (
                config("Enabled", Some("GOVERNANCE"), None, Some(101)),
                "InvalidRetentionPeriod",
            ),
        ] {
            let err = config_from_dto(Some(bad)).unwrap_err();
            assert_eq!(code(&err), expected);
            assert_eq!(err.status_code(), Some(http::StatusCode::BAD_REQUEST));
        }
        assert_eq!(code(&config_from_dto(None).unwrap_err()), "MalformedXML");
    }

    #[test]
    fn write_headers_need_a_mode_with_a_future_date() {
        let later = crate::drive::millis(now_ms() + 60_000);
        let earlier = crate::drive::millis(now_ms() - 60_000);
        let gov = dto::ObjectLockMode::from_static(dto::ObjectLockMode::GOVERNANCE);
        let on = dto::ObjectLockLegalHoldStatus::from_static(dto::ObjectLockLegalHoldStatus::ON);
        let lock = WriteLock::from_headers(Some(&gov), Some(&later), Some(&on)).unwrap();
        assert_eq!(lock.retention.unwrap().mode, LockMode::Governance);
        assert_eq!(lock.legal_hold, Some(true));
        assert!(lock.is_some());
        assert!(!WriteLock::from_headers(None, None, None).unwrap().is_some());
        let lower = dto::ObjectLockMode::from("governance".to_owned());
        let bad_hold = dto::ObjectLockLegalHoldStatus::from("on".to_owned());
        for (mode, until, hold) in [
            (Some(&gov), None, None),
            (None, Some(&later), None),
            (Some(&gov), Some(&earlier), None),
            (Some(&lower), Some(&later), None),
            (None, None, Some(&bad_hold)),
        ] {
            let err = WriteLock::from_headers(mode, until, hold).unwrap_err();
            assert_eq!(code(&err), "InvalidArgument");
        }
    }

    #[test]
    fn retention_and_legal_hold_bodies_are_checked() {
        let later = crate::drive::millis(now_ms() + 60_000);
        let body = |mode: Option<&str>, until: Option<dto::Timestamp>| dto::ObjectLockRetention {
            mode: mode.map(|m| dto::ObjectLockRetentionMode::from(m.to_owned())),
            retain_until_date: until,
        };
        let set = retention_from_dto(Some(body(Some("COMPLIANCE"), Some(later.clone()))))
            .unwrap()
            .unwrap();
        assert_eq!(set.mode, LockMode::Compliance);
        assert_eq!(retention_to_dto(&set).mode.unwrap().as_str(), "COMPLIANCE");
        assert_eq!(retention_from_dto(None).unwrap(), None);
        assert_eq!(retention_from_dto(Some(body(None, None))).unwrap(), None);
        for bad in [
            body(Some("governance"), Some(later.clone())),
            body(Some("GOVERNANCE"), None),
        ] {
            assert_eq!(
                code(&retention_from_dto(Some(bad)).unwrap_err()),
                "MalformedXML"
            );
        }
        let status = |s: &str| {
            Some(dto::ObjectLockLegalHold {
                status: Some(dto::ObjectLockLegalHoldStatus::from(s.to_owned())),
            })
        };
        assert!(legal_hold_from_dto(status("ON")).unwrap());
        assert!(!legal_hold_from_dto(status("OFF")).unwrap());
        assert_eq!(
            code(&legal_hold_from_dto(status("abc")).unwrap_err()),
            "MalformedXML"
        );
        assert_eq!(
            code(&legal_hold_from_dto(None).unwrap_err()),
            "MalformedXML"
        );
        assert_eq!(legal_hold_to_dto(false).status.unwrap().as_str(), "OFF");
    }

    #[test]
    fn a_read_shows_only_what_the_caller_may_read() {
        let attrs = ObjectAttrs {
            retention: Some(Retention {
                mode: LockMode::Governance,
                until_ms: 5_000,
            }),
            legal_hold: Some(false),
            ..ObjectAttrs::default()
        };
        let all = ReadLock::of(&attrs, true, true);
        assert_eq!(all.mode.unwrap().as_str(), "GOVERNANCE");
        assert_eq!(ms_of(&all.until.unwrap()), 5_000);
        assert_eq!(all.legal_hold.unwrap().as_str(), "OFF");
        let none = ReadLock::of(&attrs, false, false);
        assert!(none.mode.is_none() && none.until.is_none() && none.legal_hold.is_none());
    }
}
