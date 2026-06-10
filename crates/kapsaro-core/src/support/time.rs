// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Time-related helpers.

use crate::{Error, Result};
use time::OffsetDateTime;

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
