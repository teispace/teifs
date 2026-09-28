//! Reading and writing durations, counts, sizes and dates.

use std::time::{Duration, SystemTime};

/// Parses a positive number with a unit: `s`, `m`, `h` or `d` (`30s`, `12h`, `7d`).
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("`{text}` isn't a duration like 30s, 12h or 7d"))?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(format!("`{text}` needs a unit: s, m, h or d")),
    };
    let duration = number
        .checked_mul(seconds)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("`{text}` is too long"))?;
    if duration.is_zero() {
        return Err(format!("`{text}` must be longer than zero"));
    }
    Ok(duration)
}

/// Parses a count of at least one.
pub fn parse_count(text: &str) -> Result<usize, String> {
    match text.trim().parse() {
        Ok(0) | Err(_) => Err(format!("`{text}` isn't a whole number of at least 1")),
        Ok(n) => Ok(n),
    }
}

/// A time in milliseconds since the Unix epoch.
pub fn from_ms(ms: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(u64::try_from(ms).unwrap_or(0))
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn date(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `YYYY-MM-DDTHH:MM:SSZ` (RFC 3339, UTC), for `--json`.
pub fn rfc3339(time: SystemTime) -> String {
    date(time).replacen(' ', "T", 1) + "Z"
}

/// A size in bytes for people: `512 B`, `1.5 KiB`, `12.3 MiB`, `4.0 GiB`.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes;
    let mut unit = 0;
    // Tenths, in integers: exact for any u64.
    while value >= 1024 * 1024 && unit < UNITS.len() - 2 {
        value /= 1024;
        unit += 1;
    }
    let tenths = (u128::from(value) * 10 + 512) / 1024;
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit + 1])
}

/// A rate for people: `size` per second over `elapsed`.
pub fn rate(bytes: u64, elapsed: Duration) -> String {
    let millis = elapsed.as_millis().max(1);
    let per_second = u64::try_from(u128::from(bytes) * 1000 / millis).unwrap_or(u64::MAX);
    format!("{}/s", size(per_second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_counts() {
        assert_eq!(parse_duration("45s"), Ok(Duration::from_secs(45)));
        assert!(parse_duration("never").is_err());
        assert_eq!(parse_count("4096"), Ok(4096));
        for bad in ["0", "-1", "x", ""] {
            assert!(parse_count(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(date(SystemTime::UNIX_EPOCH), "1970-01-01 00:00:00");
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        assert_eq!(date(t), "2026-09-21 14:13:20");
        assert_eq!(rfc3339(t), "2026-09-21T14:13:20Z");
    }

    #[test]
    fn sizes_are_binary_units_with_one_decimal() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1024), "1.0 KiB");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(20 * 1024 * 1024), "20.0 MiB");
        assert_eq!(size(5 * 1024 * 1024 * 1024), "5.0 GiB");
        assert_eq!(size(u64::MAX), "16384.0 PiB");
        assert_eq!(rate(10 * 1024 * 1024, Duration::from_secs(2)), "5.0 MiB/s");
    }
}
