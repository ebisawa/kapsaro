// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Missing KV entry errors and the code that identifies them.
//! Marks the errors this module builds so unrelated operation failures pass through unchanged.

use crate::error::KV_KEY_NOT_FOUND_RECOVERY;
use crate::Error;

/// The one message shape a missing KV entry is reported with.
fn build_key_not_found_message(key: &str) -> String {
    format!("Key '{key}' not found")
}

pub(crate) fn build_key_not_found_error(key: &str) -> Error {
    Error::build_invalid_operation_error(build_key_not_found_message(key))
        .with_recovery(KV_KEY_NOT_FOUND_RECOVERY)
}

pub(crate) fn normalize_key_not_found_error(error: Error, key: &str) -> Error {
    if is_key_not_found_error(&error, key) {
        return build_key_not_found_error(key);
    }
    error
}

/// Whether this error is the missing-entry refusal for `key`.
///
/// The code says the error came from this module, so a look-alike message
/// raised elsewhere is not mistaken for a missing entry. The message still has
/// to name the key, because the code alone cannot say which entry was asked for.
pub(crate) fn is_key_not_found_error(error: &Error, key: &str) -> bool {
    error.recovery() == Some(KV_KEY_NOT_FOUND_RECOVERY)
        && error.format_user_message() == build_key_not_found_message(key)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_kv_error_test.rs"]
mod feature_kv_error_test;
