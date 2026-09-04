// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Applies the key expiry rules to the current clock, resolving the creation and expiry
//! timestamps a key is stored with and refusing an expiry the moment has already passed.

use crate::feature::key::validity::{enforce_expiry_after, parse_expiration};
use crate::support::time as time_util;
use crate::Result;

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
    enforce_expiry_after(expires_at, time::OffsetDateTime::now_utc())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_key_timestamp_test.rs"]
mod service_key_timestamp_test;
