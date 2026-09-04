// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Time-related helpers: RFC 3339 formatting of instants and parsing of the
//! relative durations a caller writes as a count followed by a unit letter.

use crate::{Error, Result};
use time::OffsetDateTime;

/// Seconds in one day, used to build a duration without an unchecked multiply.
const SECONDS_PER_DAY: i64 = 86_400;

/// Days a month and a year stand for in a relative duration.
const DAYS_PER_MONTH: i64 = 30;
const DAYS_PER_YEAR: i64 = 365;

/// A relative duration in both of the units its callers ask for.
///
/// The two are derived together so the day count can never name a span the
/// seconds do not hold.
pub(crate) struct RelativeDuration {
    pub(crate) days: i64,
    pub(crate) seconds: i64,
}

/// Parse a relative duration into the number of whole days it names.
///
/// The count returned always survives the multiply by seconds-per-day that
/// building a `time::Duration` performs, so a caller can hand it to
/// `time::Duration::days` without first checking it. That constructor reports an
/// overflow by panicking rather than by returning, which is why the span is
/// refused here instead.
pub fn parse_relative_duration_days(text: &str) -> Result<i64> {
    Ok(parse_relative_duration(text)?.days)
}

/// Parse a relative duration written as a count followed by a single unit letter.
///
/// A month counts as 30 days and a year as 365, so every accepted duration is a
/// whole number of days. The unit is taken as a character rather than a byte
/// slice: a duration a caller typed can end in any scalar value, and splitting
/// on the last byte would land inside a multi-byte one.
pub(crate) fn parse_relative_duration(text: &str) -> Result<RelativeDuration> {
    let text = text.trim();
    let mut characters = text.chars();
    let unit = characters
        .next_back()
        .ok_or_else(|| build_duration_syntax_error(text))?;
    let count_text = characters.as_str();
    let count: i64 = count_text
        .parse()
        .map_err(|_| build_duration_syntax_error(text))?;
    if count <= 0 {
        return Err(Error::build_parse_error(format!(
            "Duration must be positive: {}",
            text
        )));
    }

    let days = match unit {
        'd' => Some(count),
        'm' => count.checked_mul(DAYS_PER_MONTH),
        'y' => count.checked_mul(DAYS_PER_YEAR),
        _ => return Err(build_duration_syntax_error(text)),
    };
    let seconds = days
        .and_then(|days| days.checked_mul(SECONDS_PER_DAY))
        .ok_or_else(|| build_duration_out_of_range_error(text))?;
    Ok(RelativeDuration {
        days: seconds / SECONDS_PER_DAY,
        seconds,
    })
}

/// Report a duration whose shape the parser does not accept.
///
/// An empty string, a count that is not a number, and a unit outside `d`, `m`
/// and `y` are all the same mistake to whoever typed it, so one message names
/// the shape that is accepted instead of three naming the part that failed.
fn build_duration_syntax_error(duration: &str) -> Error {
    Error::build_parse_error(format!(
        "Invalid duration '{}'. Expected <number><unit> with unit d, m or y",
        duration
    ))
}

/// Report a duration too large for any instant to be measured against.
fn build_duration_out_of_range_error(duration: &str) -> Error {
    Error::build_parse_error(format!("Duration is too large: {}", duration))
}

/// Build display string for OffsetDateTime as RFC 3339 (seconds precision, no subseconds)
pub fn format_timestamp_rfc3339(dt: OffsetDateTime) -> Result<String> {
    // replace_nanosecond(0) should never fail for valid OffsetDateTime,
    // but we handle it explicitly for robustness
    let dt_zeroed = dt.replace_nanosecond(0).map_err(|e| {
        Error::build_config_error(format!("Failed to zero nanoseconds in timestamp: {}", e))
    })?;
    dt_zeroed
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::build_config_error(format!("Failed to format timestamp: {}", e)))
}

/// Get current UTC timestamp in RFC 3339 format (seconds precision)
pub fn generate_current_timestamp() -> Result<String> {
    format_timestamp_rfc3339(OffsetDateTime::now_utc())
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_time_test.rs"]
mod support_time_test;
