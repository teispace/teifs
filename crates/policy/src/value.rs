//! The typed values conditions compare: exact decimal numbers, instants, and address
//! blocks. Each parses the forms AWS accepts in policies and nothing looser.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};

/// A decimal number, exact to nine places (`NumericLessThan` on `s3:TlsVersion` 1.2
/// mustn't meet a binary rounding error). Holds anything up to ±10^29.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Number(i128);

const SCALE: i128 = 1_000_000_000;

impl Number {
    /// A whole number.
    #[must_use]
    pub fn from_int(value: i64) -> Self {
        Self(i128::from(value) * SCALE)
    }

    /// The number, when it's whole and fits in an `i64`.
    #[must_use]
    pub fn whole(self) -> Option<i64> {
        (self.0 % SCALE == 0)
            .then(|| i64::try_from(self.0 / SCALE).ok())
            .flatten()
    }

    /// `123`, `-4`, `1.25`, `+0.5`: digits with an optional sign and up to nine decimals.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (negative, digits) = match text.as_bytes().first()? {
            b'-' => (true, &text[1..]),
            b'+' => (false, &text[1..]),
            _ => (false, text),
        };
        let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
        let all_digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
        if (whole.is_empty() && fraction.is_empty())
            || !all_digits(whole)
            || !all_digits(fraction)
            || fraction.len() > 9
            || (digits.contains('.') && fraction.is_empty())
        {
            return None;
        }
        let mut value: i128 = 0;
        for b in whole.bytes().chain(fraction.bytes()) {
            value = value.checked_mul(10)?.checked_add(i128::from(b - b'0'))?;
        }
        value = value.checked_mul(10_i128.pow(9 - u32::try_from(fraction.len()).ok()?))?;
        if value > 10_i128.pow(38) {
            return None;
        }
        Some(Self(if negative { -value } else { value }))
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.0 < 0 { "-" } else { "" };
        let (whole, fraction) = (
            self.0.unsigned_abs() / SCALE.unsigned_abs(),
            self.0.unsigned_abs() % SCALE.unsigned_abs(),
        );
        if fraction == 0 {
            write!(f, "{sign}{whole}")
        } else {
            let fraction = format!("{fraction:09}");
            write!(f, "{sign}{whole}.{}", fraction.trim_end_matches('0'))
        }
    }
}

/// An instant, to the nanosecond, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date(i128);

const NANOS: i128 = 1_000_000_000;

impl Date {
    /// Now, from the system clock.
    #[must_use]
    pub fn now() -> Self {
        Self::from(SystemTime::now())
    }

    /// Seconds since 1970-01-01T00:00:00Z.
    #[must_use]
    pub fn from_unix_seconds(seconds: i64) -> Self {
        Self(i128::from(seconds) * NANOS)
    }

    /// Whole seconds since 1970-01-01T00:00:00Z (rounded down).
    #[must_use]
    pub const fn unix_seconds(self) -> i128 {
        self.0.div_euclid(NANOS)
    }

    /// The forms AWS accepts: epoch seconds (`1700000000`), or W3C ISO 8601 —
    /// `2026`, `2026-09`, `2026-09-29`, `2026-09-29T12:30Z`, `2026-09-29T12:30:00Z`,
    /// `2026-09-29T12:30:00.250+02:00`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && text.len() > 4 {
            return text.parse::<i64>().ok().map(Self::from_unix_seconds);
        }
        let (date, time) = match text.split_once(['T', 't']) {
            Some((date, time)) => (date, Some(time)),
            None => (text, None),
        };
        let mut parts = date.split('-');
        let year = fixed(parts.next()?, 4)?;
        let month = parts.next().map_or(Some(1), |m| fixed(m, 2))?;
        let day = parts.next().map_or(Some(1), |d| fixed(d, 2))?;
        if parts.next().is_some()
            || !(1..=12).contains(&month)
            || !(1..=days_in_month(year, month)).contains(&day)
            || (time.is_some() && date.len() != 10)
        {
            return None;
        }
        let mut nanos = i128::from(days_from_civil(year, month, day)) * 86_400 * NANOS;
        if let Some(time) = time {
            nanos += time_of_day(time)?;
        }
        Some(Self(nanos))
    }
}

impl From<SystemTime> for Date {
    fn from(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => Self(i128::try_from(after.as_nanos()).unwrap_or(i128::MAX)),
            Err(before) => Self(-i128::try_from(before.duration().as_nanos()).unwrap_or(i128::MAX)),
        }
    }
}

impl fmt::Display for Date {
    /// `2026-09-29T12:30:00Z`, with a fraction only when there is one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.0.div_euclid(NANOS);
        let nanos = self.0.rem_euclid(NANOS);
        let days = seconds.div_euclid(86_400);
        let of_day = seconds.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
            of_day / 3600,
            of_day / 60 % 60,
            of_day % 60
        )?;
        if nanos != 0 {
            write!(f, ".{}", format!("{nanos:09}").trim_end_matches('0'))?;
        }
        f.write_str("Z")
    }
}

/// Exactly `len` ASCII digits.
fn fixed(text: &str, len: usize) -> Option<i64> {
    (text.len() == len && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// `hh:mm[:ss[.fraction]]` then `Z` or `±hh:mm`, as nanoseconds after midnight UTC.
fn time_of_day(text: &str) -> Option<i128> {
    let zone_at = text.find(['Z', 'z', '+', '-'])?;
    let (clock, zone) = text.split_at(zone_at);
    let offset = match zone {
        "Z" | "z" => 0,
        _ => {
            let (hours, minutes) = zone[1..].split_once(':')?;
            let (hours, minutes) = (fixed(hours, 2)?, fixed(minutes, 2)?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let offset = (hours * 60 + minutes) * 60;
            if zone.starts_with('-') {
                -offset
            } else {
                offset
            }
        }
    };
    let mut fields = clock.split(':');
    let hours = fixed(fields.next()?, 2)?;
    let minutes = fixed(fields.next()?, 2)?;
    let (seconds, fraction) = match fields.next() {
        Some(seconds) => {
            let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
            if seconds.contains('.')
                && (fraction.is_empty()
                    || fraction.len() > 9
                    || !fraction.bytes().all(|b| b.is_ascii_digit()))
            {
                return None;
            }
            let nanos = if fraction.is_empty() {
                0
            } else {
                fraction.parse::<i128>().ok()?
                    * 10_i128.pow(9 - u32::try_from(fraction.len()).ok()?)
            };
            (fixed(whole, 2)?, nanos)
        }
        None => (0, 0),
    };
    if fields.next().is_some() || hours > 23 || minutes > 59 || seconds > 59 {
        return None;
    }
    let local = i128::from(hours * 3600 + minutes * 60 + seconds);
    Some((local - i128::from(offset)) * NANOS + fraction)
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The calendar date `days` after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// An address block: `203.0.113.0/24`, `2001:db8::/32`, or one address (`/32`, `/128`).
/// IPv4 addresses written as IPv6 (`::ffff:203.0.113.5`) are IPv4, on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses a block or a single address. Host bits are allowed and ignored, as AWS does.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address.parse().ok()?;
        let mapped = matches!(address, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some());
        let address = address.to_canonical();
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(prefix) if prefix.bytes().all(|b| b.is_ascii_digit()) && !prefix.is_empty() => {
                let prefix: u8 = prefix.parse().ok()?;
                // A mapped IPv4 block counts its prefix over the 128 bits.
                if mapped {
                    prefix.checked_sub(96)?
                } else {
                    prefix
                }
            }
            Some(_) => return None,
        };
        (prefix <= max).then(|| Self {
            network: mask(address, prefix),
            prefix,
        })
    }

    /// Whether `address` is in the block.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        address.is_ipv4() == self.network.is_ipv4() && mask(address, self.prefix) == self.network
    }

    /// Whether S3 counts the block as a fixed set of addresses rather than the public:
    /// at most a `/8` of IPv4, a `/32` of IPv6.
    pub(crate) fn is_narrow(&self) -> bool {
        self.prefix >= if self.network.is_ipv4() { 8 } else { 32 }
    }
}

fn mask(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(bits))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(bits))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_exact_decimals() {
        let n = Number::parse;
        assert_eq!(n("1.2"), n("1.20"));
        assert!(n("1.2") < n("1.3") && n("-1") < n("0") && n("10") > n("9.999999999"));
        assert_eq!(n("+5"), Some(Number::from_int(5)));
        assert_eq!(n("0.000000001").unwrap().to_string(), "0.000000001");
        assert_eq!(n("-12.50").unwrap().to_string(), "-12.5");
        assert_eq!(n("100").unwrap().to_string(), "100");
        assert_eq!(n(".5"), n("0.5"));
        for bad in [
            "",
            "-",
            "+",
            ".",
            "1.",
            "1e3",
            "0x10",
            "1.0000000001",
            "1 ",
            " 1",
            "1,5",
            "NaN",
            "--1",
        ] {
            assert_eq!(n(bad), None, "{bad:?}");
        }
        assert!(n(&"9".repeat(40)).is_none(), "too large");
        assert!(n(&"9".repeat(29)).is_some());
    }

    #[test]
    fn dates_in_every_form_aws_accepts() {
        let d = |text: &str| Date::parse(text).map(|date| date.to_string());
        assert_eq!(
            d("2026-09-29T12:30:00Z").as_deref(),
            Some("2026-09-29T12:30:00Z")
        );
        assert_eq!(
            d("2026-09-29T12:30Z").as_deref(),
            Some("2026-09-29T12:30:00Z")
        );
        assert_eq!(d("2026-09-29").as_deref(), Some("2026-09-29T00:00:00Z"));
        assert_eq!(d("2026-09").as_deref(), Some("2026-09-01T00:00:00Z"));
        assert_eq!(d("2026").as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(
            d("2026-09-29T14:30:00+02:00").as_deref(),
            Some("2026-09-29T12:30:00Z")
        );
        assert_eq!(
            d("2026-09-29T00:30:00-01:00").as_deref(),
            Some("2026-09-29T01:30:00Z")
        );
        assert_eq!(
            d("2026-09-29T12:30:00.25Z").as_deref(),
            Some("2026-09-29T12:30:00.25Z")
        );
        assert_eq!(d("1800000000").as_deref(), Some("2027-01-15T08:00:00Z"));
        assert_eq!(d("2000-02-29").as_deref(), Some("2000-02-29T00:00:00Z"));
        assert_eq!(
            d("1969-12-31T23:59:59Z").as_deref(),
            Some("1969-12-31T23:59:59Z")
        );
        for bad in [
            "",
            "2026-13-01",
            "2026-02-29",
            "2100-02-29",
            "2026-09-31",
            "2026-9-1",
            "26-09-29",
            "2026-09-29T24:00:00Z",
            "2026-09-29T12:60Z",
            "2026-09-29T12:30:00",
            "2026-09-29T12:30:61Z",
            "2026-09-29T12:30:00.Z",
            "2026-09-29T12:30:00+2:00",
            "2026-09T12:00Z",
            "yesterday",
            "2026-09-29T12:30:00Z ",
            "12:30:00Z",
        ] {
            assert_eq!(d(bad), None, "{bad:?}");
        }
        assert!(
            Date::parse("2026-09-29T12:30:00Z") < Date::parse("2026-09-29T12:30:00.000000001Z")
        );
        assert_eq!(
            Date::parse("1970-01-01T00:00:01Z").unwrap().unix_seconds(),
            1
        );
    }

    #[test]
    fn calendar_round_trips() {
        for days in (-800_000..800_000).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn address_blocks() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let block = Cidr::parse("203.0.113.0/24").unwrap();
        assert!(block.contains(ip("203.0.113.200")));
        assert!(!block.contains(ip("203.0.114.1")));
        assert!(
            block.contains(ip("::ffff:203.0.113.7")),
            "a mapped address is IPv4"
        );
        assert!(!block.contains(ip("2001:db8::1")));
        assert!(
            Cidr::parse("203.0.113.5/24")
                .unwrap()
                .contains(ip("203.0.113.9")),
            "host bits ignored"
        );
        let one = Cidr::parse("198.51.100.7").unwrap();
        assert!(one.contains(ip("198.51.100.7")) && !one.contains(ip("198.51.100.8")));
        let six = Cidr::parse("2001:db8::/32").unwrap();
        assert!(six.contains(ip("2001:db8:ffff::1")) && !six.contains(ip("2001:db9::1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(!Cidr::parse("0.0.0.0/0").unwrap().contains(ip("::1")));
        let narrow = |text: &str| Cidr::parse(text).unwrap().is_narrow();
        assert!(narrow("10.0.0.0/8") && narrow("203.0.113.9") && narrow("2001:db8::/32"));
        assert!(!narrow("0.0.0.0/7") && !narrow("2001::/31") && !narrow("::ffff:0.0.0.0/100"));
        assert!(
            Cidr::parse("::ffff:10.0.0.0/104")
                .unwrap()
                .contains(ip("10.1.2.3"))
        );
        for bad in [
            "",
            "10.0.0.0/33",
            "::/129",
            "10.0.0/8",
            "10.0.0.0/",
            "10.0.0.0/x",
            "10.0.0.0/+8",
            "host",
            "::ffff:10.0.0.0/90",
        ] {
            assert_eq!(Cidr::parse(bad), None, "{bad:?}");
        }
    }
}
