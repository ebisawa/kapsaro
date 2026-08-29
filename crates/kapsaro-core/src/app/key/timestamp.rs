// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Resolves key creation and expiration timestamps from CLI arguments, taking either an explicit
//! RFC3339 expiry or a relative duration like "30d", and says whether a resolved expiry still holds.

use crate::support::time as time_util;
use crate::{Error, Result};

pub fn resolve_key_timestamps(
    expires_at_arg: &Option<String>,
    valid_for_arg: &Option<String>,
) -> Result<(String, String)> {
    let created_at = time::OffsetDateTime::now_utc();
    let expires_at = parse_expiration(expires_at_arg, valid_for_arg, created_at)?;

    Ok((
        time_util::format_timestamp_rfc3339(created_at)?,
        time_util::format_timestamp_rfc3339(expires_at)?,
    ))
}

/// Refuse an expiry that has been reached by the time it is checked.
///
/// The expiry is resolved when the command starts and the key is stored much
/// later: the SSH steps and the GitHub lookup in between take an operator's
/// input and a network round trip. A key whose expiry passed in that window is
/// refused before it is written, because the keystore refuses to activate it
/// afterwards and the pair would stay behind unusable.
pub(crate) fn ensure_expiry_not_reached(expires_at: &str) -> Result<()> {
    ensure_expiry_after(expires_at, time::OffsetDateTime::now_utc())
}

/// The keystore treats an expiry it has reached as expired, so the same
/// boundary decides here: an expiry equal to `now` is refused.
fn ensure_expiry_after(expires_at: &str, now: time::OffsetDateTime) -> Result<()> {
    if parse_rfc3339(expires_at, "key expiry")? > now {
        return Ok(());
    }
    Err(Error::build_config_error(format!(
        "Key expiry '{}' was reached before the key could be stored, so the key would already be \
         expired. Run the command again, giving a later expiry with --expires-at or --valid-for.",
        expires_at
    )))
}

fn parse_rfc3339(value: &str, subject: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_err(
        |e| {
            Error::build_parse_error_with_source(
                format!("Invalid {} format (expected RFC3339): {}", subject, e),
                e,
            )
        },
    )
}

/// How long a key stays valid when neither expiry argument is given.
const DEFAULT_VALIDITY: &str = "365d";
const DEFAULT_VALIDITY_DAYS: i64 = 365;

/// Resolve the expiry every branch measures from the recorded creation time.
///
/// The timestamp stored as `created_at` is the one a relative duration is added
/// to, so the recorded creation time and the expiry it implies always agree.
fn parse_expiration(
    expires_at: &Option<String>,
    valid_for: &Option<String>,
    created_at: time::OffsetDateTime,
) -> Result<time::OffsetDateTime> {
    if expires_at.is_some() && valid_for.is_some() {
        return Err(Error::build_config_error(
            "cannot specify both --expires-at and --valid-for".to_string(),
        ));
    }

    if let Some(datetime_str) = expires_at {
        let parsed = parse_rfc3339(datetime_str, "--expires-at")?;
        if parsed <= created_at {
            return Err(Error::build_config_error(format!(
                "--expires-at must be after key creation time: {}",
                datetime_str
            )));
        }
        Ok(parsed)
    } else if let Some(duration_str) = valid_for {
        let duration = parse_duration(duration_str)?;
        created_at
            .checked_add(duration)
            .ok_or_else(|| build_duration_out_of_range_error(duration_str))
    } else {
        created_at
            .checked_add(time::Duration::days(DEFAULT_VALIDITY_DAYS))
            .ok_or_else(|| build_duration_out_of_range_error(DEFAULT_VALIDITY))
    }
}

/// Seconds in one day, used to build a duration without an unchecked multiply.
const SECONDS_PER_DAY: i64 = 86_400;

/// Parse a duration written as a count followed by a single unit letter.
///
/// The unit is taken as a character rather than a byte slice: a duration a
/// caller typed can end in any scalar value, and splitting on the last byte
/// would land inside a multi-byte one.
fn parse_duration(s: &str) -> Result<time::Duration> {
    let s = s.trim();
    let mut characters = s.chars();
    let unit = characters
        .next_back()
        .ok_or_else(|| Error::build_parse_error("Empty duration string".to_string()))?;
    let num_str = characters.as_str();
    let num: i64 = num_str
        .parse()
        .map_err(|_| Error::build_parse_error(format!("Invalid duration number: {}", num_str)))?;
    if num <= 0 {
        return Err(Error::build_parse_error(format!(
            "Duration must be positive: {}",
            s
        )));
    }

    let days = match unit {
        'd' => Some(num),
        'm' => num.checked_mul(30),
        'y' => num.checked_mul(365),
        _ => {
            return Err(Error::build_parse_error(format!(
                "Invalid duration unit: {} (expected d, m, or y)",
                unit
            )))
        }
    };

    days.and_then(|days| days.checked_mul(SECONDS_PER_DAY))
        .map(time::Duration::seconds)
        .ok_or_else(|| build_duration_out_of_range_error(s))
}

/// Report a duration that no expiry timestamp can represent.
///
/// The count parses as a number and the unit is one this accepts, so the
/// refusal names the span rather than the syntax.
fn build_duration_out_of_range_error(duration: &str) -> Error {
    Error::build_parse_error(format!(
        "Duration is too large to reach an expiry date: {}",
        duration
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_key_timestamp_test.rs"]
mod app_key_timestamp_test;
