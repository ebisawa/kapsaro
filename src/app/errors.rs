// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer error helpers.

use crate::support::path::format_path_relative_to_cwd;
use crate::Error;
use std::path::Path;

#[cfg(test)]
#[path = "../../tests/unit/internal/app_errors_test.rs"]
mod tests;

/// Build a KV key-not-found error with file path context when applicable.
pub fn build_kv_key_not_found_error(error: Error, input_path: &Path, key: &str) -> Error {
    if let Some(message) = kv_key_not_found_message(&error, key) {
        return build_kv_key_file_not_found_error(message, input_path);
    }
    error
}

fn kv_key_not_found_message<'a>(error: &'a Error, key: &str) -> Option<&'a str> {
    match error {
        Error::InvalidOperation { message }
            if is_invalid_operation_kv_key_not_found(message, key) =>
        {
            Some(message)
        }
        Error::NotFound { message } if is_not_found_kv_key_not_found(message, key) => Some(message),
        _ => None,
    }
}

fn is_invalid_operation_kv_key_not_found(message: &str, key: &str) -> bool {
    let quoted = format!("Key '{}' not found", key);
    let unquoted = format!("Key not found: {}", key);
    message == quoted || message == unquoted
}

fn is_not_found_kv_key_not_found(message: &str, key: &str) -> bool {
    message.contains(key) && message.contains("not found")
}

fn build_kv_key_file_not_found_error(message: &str, input_path: &Path) -> Error {
    Error::NotFound {
        message: format!("{} in {}", message, format_path_relative_to_cwd(input_path)),
    }
}

/// Serialize a value to `serde_json::Value`, mapping the error to `Error::Parse`.
pub fn serialize_to_json_value<T: serde::Serialize>(value: &T) -> crate::Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| crate::Error::Parse {
        message: format!("Failed to serialize member document: {}", e),
        source: Some(Box::new(e)),
    })
}

/// Build the default missing KV file error shown by KV commands.
pub fn build_default_kv_file_not_found_error(file_path: &Path) -> Error {
    Error::NotFound {
        message: format!(
            "Default kv file not found: {}. Use 'secretenv set' to create it.",
            format_path_relative_to_cwd(file_path)
        ),
    }
}

/// Wrap any local trust store load/verification failure into a reset-required error.
pub fn build_invalid_trust_store_error(path: &Path, error: Error) -> Error {
    Error::Verify {
        rule: "E_TRUST_STORE_RESET_REQUIRED".to_string(),
        message: format!(
            "Local trust store '{}' is invalid and must be reset: {}",
            format_path_relative_to_cwd(path),
            error.format_user_message()
        ),
    }
}
