// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer error helpers.

use crate::support::path::display_path_relative_to_cwd;
use crate::Error;
use std::path::Path;

#[cfg(test)]
#[path = "../../tests/unit/app_errors_test.rs"]
mod tests;

/// Add file path context to key-not-found errors from KV commands.
pub fn handle_kv_key_not_found_error(error: Error, input_path: &Path, key: &str) -> Error {
    match &error {
        Error::InvalidOperation { message } => {
            let expected_pattern = format!("Key '{}' not found", key);
            let expected_pattern_no_quotes = format!("Key not found: {}", key);
            if message == &expected_pattern || message == &expected_pattern_no_quotes {
                return Error::NotFound {
                    message: format!(
                        "{} in {}",
                        message,
                        display_path_relative_to_cwd(input_path)
                    ),
                };
            }
        }
        Error::NotFound { message } => {
            if message.contains(key) && message.contains("not found") {
                return Error::NotFound {
                    message: format!(
                        "{} in {}",
                        message,
                        display_path_relative_to_cwd(input_path)
                    ),
                };
            }
        }
        _ => {}
    }
    error
}

/// Serialize a value to `serde_json::Value`, mapping the error to `Error::Parse`.
pub fn serialize_to_json_value<T: serde::Serialize>(value: &T) -> crate::Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| crate::Error::Parse {
        message: format!("Failed to serialize member document: {}", e),
        source: Some(Box::new(e)),
    })
}

/// Build the default missing KV file error shown by KV workflows.
pub fn default_kv_file_not_found_error(file_path: &Path) -> Error {
    Error::NotFound {
        message: format!(
            "Default kv file not found: {}. Use 'secretenv set' to create it.",
            display_path_relative_to_cwd(file_path)
        ),
    }
}

/// Wrap any local trust store load/verification failure into a reset-required error.
pub fn build_invalid_trust_store_error(path: &Path, error: Error) -> Error {
    Error::Verify {
        rule: "E_TRUST_STORE_RESET_REQUIRED".to_string(),
        message: format!(
            "Local trust store '{}' is invalid and must be reset: {}",
            display_path_relative_to_cwd(path),
            error.user_message()
        ),
    }
}
