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

/// Now, in milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// A time in milliseconds since the Unix epoch as a TOML date and time (UTC).
pub fn datetime(ms: i64) -> toml::value::Datetime {
    rfc3339(from_ms(ms))
        .parse()
        .expect("RFC 3339 text is a TOML date and time")
}

/// A TOML date and time with an offset, in milliseconds since the Unix epoch; none for
/// one without a date, a time or an offset (a local time says no moment).
pub fn datetime_ms(at: &toml::value::Datetime) -> Option<i64> {
    let (date, time) = (at.date?, at.time?);
    let offset_minutes = match at.offset? {
        toml::value::Offset::Z => 0,
        toml::value::Offset::Custom { minutes } => i64::from(minutes),
    };
    let days = days_from_civil(
        i64::from(date.year),
        u32::from(date.month),
        u32::from(date.day),
    );
    let seconds = days * 86_400
        + i64::from(time.hour) * 3600
        + i64::from(time.minute) * 60
        + i64::from(time.second.unwrap_or(0))
        - offset_minutes * 60;
    Some(seconds * 1000 + i64::from(time.nanosecond.unwrap_or(0) / 1_000_000))
}

/// A day, `YYYY-MM-DD`, as its midnight UTC in milliseconds since the Unix epoch.
pub fn parse_day(text: &str) -> Result<i64, String> {
    let bad = || format!("`{text}` isn't a date: write it like 2026-10-01");
    let mut parts = text.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let (y, m, d): (i64, u32, u32) = (
        y.parse().map_err(|_| bad())?,
        m.parse().map_err(|_| bad())?,
        d.parse().map_err(|_| bad())?,
    );
    let days = days_from_civil(y, m, d);
    // Only real dates: one that doesn't come back the same (2026-02-30) isn't.
    if !(1..=12).contains(&m) || civil_from_days(days) != (y, m, d) {
        return Err(bad());
    }
    Ok(days * 86_400_000)
}

/// A calendar date to days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses a size: bytes, or a number with `KiB`, `MiB` or `GiB` (`K`, `M`, `G` too).
pub fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("`{text}` isn't a size like 8MiB"))?;
    let unit: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kib" => 1 << 10,
        "m" | "mib" => 1 << 20,
        "g" | "gib" => 1 << 30,
        _ => return Err(format!("`{text}` needs a unit: KiB, MiB or GiB")),
    };
    number
        .checked_mul(unit)
        .ok_or_else(|| format!("`{text}` is too large"))
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
    fn toml_times_are_moments() {
        for ms in [
            0,
            1_000,
            951_782_400_000,
            1_790_000_000_123,
            4_102_444_800_000,
        ] {
            assert_eq!(datetime_ms(&datetime(ms)), Some(ms / 1000 * 1000), "{ms}");
        }
        let at = |text: &str| datetime_ms(&text.parse().unwrap());
        assert_eq!(at("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(at("1969-12-31T23:30:00-00:30"), Some(0));
        assert_eq!(at("2000-02-29T00:00:00.250Z"), Some(951_782_400_250));
        assert_eq!(at("2000-02-29T00:00:00"), None);
        assert_eq!(at("2000-02-29"), None);
        assert_eq!(at("00:00:00"), None);
    }

    #[test]
    fn sizes_parse_with_units() {
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("10"), Ok(10));
        assert_eq!(parse_size("10B"), Ok(10));
        assert_eq!(parse_size("2K"), Ok(2048));
        assert_eq!(parse_size(" 3 MiB "), Ok(3 << 20));
        assert_eq!(parse_size("1g"), Ok(1 << 30));
        assert_eq!(parse_size("17179869183G"), Ok(17_179_869_183 << 30));
        for bad in ["", "MiB", "-1", "1.5M", "8MB", "1T", "17179869184G"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

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
        assert_eq!(parse_day("1970-01-01"), Ok(0));
        assert_eq!(
            parse_day("2026-09-21").map(from_ms).map(date).as_deref(),
            Ok("2026-09-21 00:00:00")
        );
        assert_eq!(parse_day("2024-02-29"), Ok(19_782 * 86_400_000));
        for bad in [
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "26-01-01",
            "2026-1-01",
            "2026-01-01-",
            "tomorrow",
        ] {
            assert!(parse_day(bad).is_err(), "{bad}");
        }
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
