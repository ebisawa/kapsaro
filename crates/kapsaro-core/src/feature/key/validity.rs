// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rules a key expiry follows: the instant a caller's expiry argument resolves to
//! against a given creation time, and whether an expiry still lies ahead of a given moment.

use crate::support::time::parse_relative_duration;
use crate::{Error, Result};

/// How long a key stays valid when neither expiry argument is given.
const DEFAULT_VALIDITY: &str = "365d";
const DEFAULT_VALIDITY_DAYS: i64 = 365;

/// Resolve the expiry every branch measures from the recorded creation time.
///
/// The timestamp stored as `created_at` is the one a relative duration is added
/// to, so the recorded creation time and the expiry it implies always agree.
pub(crate) fn parse_expiration(
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

/// The keystore treats an expiry it has reached as expired, so the same
/// boundary decides here: an expiry equal to `now` is refused.
pub(crate) fn enforce_expiry_after(expires_at: &str, now: time::OffsetDateTime) -> Result<()> {
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

/// Turn the day count a relative duration names into a duration.
fn parse_duration(text: &str) -> Result<time::Duration> {
    Ok(time::Duration::seconds(
        parse_relative_duration(text)?.seconds,
    ))
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
#[path = "../../../tests/unit/internal/feature_key_validity_test.rs"]
mod feature_key_validity_test;
