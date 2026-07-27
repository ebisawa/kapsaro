// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV error helpers shared by app and facade adapters.
//! Centralizes missing-entry detection so unrelated operation errors pass through unchanged.

use crate::{Error, ErrorKind};

pub(crate) fn build_key_not_found_error(key: &str) -> Error {
    Error::build_invalid_operation_error(format!("Key '{}' not found", key))
}

pub(crate) fn normalize_key_not_found_error(error: Error, key: &str) -> Error {
    if is_key_not_found_error(&error, key) {
        return build_key_not_found_error(key);
    }
    error
}

pub(crate) fn is_key_not_found_error(error: &Error, key: &str) -> bool {
    let message = error.format_user_message();
    match error.kind() {
        ErrorKind::InvalidOperation => is_invalid_operation_key_not_found(message, key),
        _ => false,
    }
}

fn is_invalid_operation_key_not_found(message: &str, key: &str) -> bool {
    let quoted = format!("Key '{}' not found", key);
    let unquoted = format!("Key not found: {}", key);
    message == quoted || message == unquoted
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_kv_error_test.rs"]
mod feature_kv_error_test;
