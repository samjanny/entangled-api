//! `EntangledTimestamp`: strict `YYYY-MM-DDTHH:MM:SSZ` UTC timestamp (§02).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

const TIMESTAMP_LEN: usize = 20;

/// A strict UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` form (§02).
///
/// The wire form is exactly 20 ASCII characters, second-resolution, always
/// in UTC (`Z` suffix). Leap seconds are not permitted. Calendar validity
/// is enforced at parse time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntangledTimestamp(OffsetDateTime);

/// Reasons a string fails to parse as an [`EntangledTimestamp`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TimestampError {
    /// The string does not match the fixed `YYYY-MM-DDTHH:MM:SSZ` shape.
    #[error("timestamp must be exactly 20 ASCII characters in YYYY-MM-DDTHH:MM:SSZ form")]
    BadShape,
    /// Month component is outside 01..=12.
    #[error("timestamp month is out of range (01..=12)")]
    InvalidMonth,
    /// Day component is outside 01..=31.
    #[error("timestamp day is out of range (01..=31)")]
    InvalidDay,
    /// Hour component is outside 00..=23.
    #[error("timestamp hour is out of range (00..=23)")]
    InvalidHour,
    /// Minute component is outside 00..=59.
    #[error("timestamp minute is out of range (00..=59)")]
    InvalidMinute,
    /// Second component is outside 00..=59 (leap seconds rejected).
    #[error("timestamp second is out of range (00..=59); leap seconds are not permitted")]
    InvalidSecond,
    /// The day does not exist in the given month/year (e.g., Feb 30).
    #[error("timestamp is not a valid calendar date")]
    InvalidDate,
}

impl EntangledTimestamp {
    /// Seconds since the Unix epoch (1970-01-01T00:00:00Z).
    pub fn unix_timestamp(&self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Convert to the underlying `time::OffsetDateTime` (always UTC).
    pub fn as_offset_date_time(&self) -> OffsetDateTime {
        self.0
    }
}

impl std::ops::Add<time::Duration> for EntangledTimestamp {
    type Output = Self;

    fn add(self, rhs: time::Duration) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::Sub<time::Duration> for EntangledTimestamp {
    type Output = Self;

    fn sub(self, rhs: time::Duration) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl std::ops::Sub<EntangledTimestamp> for EntangledTimestamp {
    type Output = time::Duration;

    fn sub(self, rhs: EntangledTimestamp) -> Self::Output {
        self.0 - rhs.0
    }
}

fn parse_two_digits(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 2 {
        return None;
    }
    let a = bytes[0];
    let b = bytes[1];
    if !a.is_ascii_digit() || !b.is_ascii_digit() {
        return None;
    }
    Some(u32::from(a - b'0') * 10 + u32::from(b - b'0'))
}

fn parse_four_digits(bytes: &[u8]) -> Option<i32> {
    if bytes.len() != 4 {
        return None;
    }
    let mut acc: i32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc * 10 + i32::from(b - b'0');
    }
    Some(acc)
}

impl<'a> TryFrom<&'a str> for EntangledTimestamp {
    type Error = TimestampError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.len() != TIMESTAMP_LEN {
            return Err(TimestampError::BadShape);
        }
        let bytes = value.as_bytes();
        // Shape: YYYY-MM-DDTHH:MM:SSZ
        //        0123456789012345678901
        if bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'Z'
        {
            return Err(TimestampError::BadShape);
        }
        let year = parse_four_digits(&bytes[0..4]).ok_or(TimestampError::BadShape)?;
        let month_n = parse_two_digits(&bytes[5..7]).ok_or(TimestampError::BadShape)?;
        let day_n = parse_two_digits(&bytes[8..10]).ok_or(TimestampError::BadShape)?;
        let hour_n = parse_two_digits(&bytes[11..13]).ok_or(TimestampError::BadShape)?;
        let min_n = parse_two_digits(&bytes[14..16]).ok_or(TimestampError::BadShape)?;
        let sec_n = parse_two_digits(&bytes[17..19]).ok_or(TimestampError::BadShape)?;

        if !(1..=12).contains(&month_n) {
            return Err(TimestampError::InvalidMonth);
        }
        if !(1..=31).contains(&day_n) {
            return Err(TimestampError::InvalidDay);
        }
        if hour_n > 23 {
            return Err(TimestampError::InvalidHour);
        }
        if min_n > 59 {
            return Err(TimestampError::InvalidMinute);
        }
        if sec_n > 59 {
            return Err(TimestampError::InvalidSecond);
        }

        let month: Month = match month_n {
            1 => Month::January,
            2 => Month::February,
            3 => Month::March,
            4 => Month::April,
            5 => Month::May,
            6 => Month::June,
            7 => Month::July,
            8 => Month::August,
            9 => Month::September,
            10 => Month::October,
            11 => Month::November,
            12 => Month::December,
            _ => unreachable!(),
        };

        let date = Date::from_calendar_date(year, month, day_n as u8)
            .map_err(|_| TimestampError::InvalidDate)?;
        // SAFETY: ranges already validated above; from_hms returns Err only for out-of-range.
        let time_v = Time::from_hms(hour_n as u8, min_n as u8, sec_n as u8)
            .map_err(|_| TimestampError::InvalidDate)?;
        let primitive = PrimitiveDateTime::new(date, time_v);
        Ok(Self(primitive.assume_utc()))
    }
}

impl TryFrom<String> for EntangledTimestamp {
    type Error = TimestampError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Display for EntangledTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dt = self.0;
        let year = dt.year();
        let month = u8::from(dt.month());
        let day = dt.day();
        let hour = dt.hour();
        let minute = dt.minute();
        let second = dt.second();
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        )
    }
}

impl Serialize for EntangledTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EntangledTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}
