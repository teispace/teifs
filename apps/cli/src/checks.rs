//! Checks as `teifs status` and `teifs doctor` report them: each named, with how it went
//! and what it found, printed as a table or a record each, and exit code 1 when one
//! failed. What both judge the same way (a certificate's expiry, a disk's room) is here.

use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde_json::{Value, json};

use crate::{error::Error, plural, ui, units};

/// How soon a certificate's expiry is worth a warning.
const CERTIFICATE_WARNING: Duration = Duration::from_hours(14 * 24);

/// How a check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum State {
    Ok,
    Warning,
    Failed,
}

/// One check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Check {
    pub name: &'static str,
    pub state: State,
    pub detail: String,
}

impl Check {
    pub(crate) fn new(name: &'static str, state: State, detail: impl Into<String>) -> Self {
        Self {
            name,
            state,
            detail: detail.into(),
        }
    }

    /// A check named `name` that found `found`.
    pub(crate) fn named(name: &'static str, (state, detail): (State, String)) -> Self {
        Self::new(name, state, detail)
    }
}

/// Prints the checks, a table or a record each with `about` (`(field, value)`: what was
/// checked), and fails with exit code 1 when one failed.
pub(crate) fn finish(checks: &[Check], about: (&str, &str)) -> Result<(), Error> {
    let records: Vec<Value> = checks
        .iter()
        .map(|check| {
            let mut record = json!({"type": "check", about.0: about.1});
            if let (Value::Object(record), Ok(Value::Object(fields))) =
                (&mut record, serde_json::to_value(check))
            {
                record.extend(fields);
            }
            record
        })
        .collect();
    let mut table = ui::Table::new(&["CHECK", "STATE", "DETAIL"]);
    for check in checks {
        let state = match check.state {
            State::Ok => "ok",
            State::Warning => "warning",
            State::Failed => "failed",
        };
        table.row(vec![
            check.name.to_owned(),
            state.to_owned(),
            check.detail.clone(),
        ]);
    }
    ui::rows(&table, &records, "No checks.");
    let failed = checks.iter().filter(|c| c.state == State::Failed).count() as u64;
    if failed > 0 {
        return Err(Error::general(format!("{failed} check{} failed", plural(failed))).shown());
    }
    Ok(())
}

/// When a certificate (DER) stops being valid, if it can be read.
pub(crate) fn not_after(der: &[u8]) -> Option<SystemTime> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let seconds = certificate.validity().not_after.timestamp();
    Some(units::from_ms(seconds.saturating_mul(1000)))
}

/// What a certificate's expiry (`not_after`, if it could be read) means at `now`.
pub(crate) fn expiry(not_after: Option<SystemTime>, now: SystemTime) -> (State, String) {
    let Some(not_after) = not_after else {
        return (State::Failed, "the certificate can't be read".to_owned());
    };
    let until = units::date(not_after);
    match not_after.duration_since(now) {
        Err(_) => (
            State::Failed,
            format!("expired {until}: clients refuse the server; renew it"),
        ),
        Ok(left) if left < CERTIFICATE_WARNING => (
            State::Warning,
            format!(
                "expires {until}, in {} days: renew it",
                left.as_secs() / (24 * 60 * 60)
            ),
        ),
        Ok(_) => (State::Ok, format!("valid until {until}")),
    }
}

/// What a disk's room means: full when nothing's left beyond what's kept free for
/// deletes (writes are refused), nearly full below 5 % of its size.
pub(crate) fn disk(path: &str, total: u64, free: u64, reserved: u64) -> (State, String) {
    let size = units::size;
    let room = free.saturating_sub(reserved);
    let detail = format!("{path}: {} free of {}", size(free), size(total));
    if room == 0 {
        (
            State::Failed,
            format!("{detail}: full, writes are refused (delete objects, or give it more room)"),
        )
    } else if room < total / 20 {
        (State::Warning, format!("{detail}: nearly full"))
    } else {
        (State::Ok, detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_mins(1);

    #[test]
    fn certificates_are_told_by_when_they_expire() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let day = 24 * 60 * MINUTE;
        assert_eq!(expiry(Some(now + 30 * day), now).0, State::Ok);
        let soon = expiry(Some(now + 13 * day), now);
        assert_eq!(soon.0, State::Warning);
        assert!(soon.1.ends_with("in 13 days: renew it"), "{}", soon.1);
        assert_eq!(expiry(Some(now + 14 * day), now).0, State::Ok);
        assert_eq!(expiry(Some(now - day), now).0, State::Failed);
        assert_eq!(expiry(None, now).0, State::Failed);
    }

    #[test]
    fn a_certificates_expiry_is_read() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["s3.test".to_owned()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 1, 2);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let expected = SystemTime::UNIX_EPOCH + Duration::from_hours(22_281 * 24);
        assert_eq!(not_after(&der), Some(expected));
        assert_eq!(not_after(b"not a certificate"), None);
    }

    #[test]
    fn disks_are_told_by_their_room() {
        let gib = 1 << 30;
        assert_eq!(disk("/d", 100 * gib, 50 * gib, gib).0, State::Ok);
        assert_eq!(disk("/d", 100 * gib, 6 * gib, gib).0, State::Ok);
        assert_eq!(disk("/d", 100 * gib, 5 * gib, gib).0, State::Warning);
        assert_eq!(disk("/d", 100 * gib, gib, gib).0, State::Failed);
        assert_eq!(disk("/d", 100 * gib, 0, gib).0, State::Failed);
        assert_eq!(
            disk("/d", 100 * gib, 50 * gib, gib).1,
            "/d: 50.0 GiB free of 100.0 GiB"
        );
    }
}
