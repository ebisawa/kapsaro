// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Dotenv format parser
//!
//! Provides functions to parse dotenv-style KEY=VALUE pairs with support for
//! quoted values and escape sequences.

use crate::support::secret::SecretString;
use crate::{Error, Result};
use std::collections::HashMap;

// ============================================================================
// Dotenv Parsing
// ============================================================================

/// Check if a key name is valid: `[A-Za-z_][A-Za-z0-9_]*`
pub fn is_valid_key_name(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Unquote a value from dotenv format
pub fn parse_dotenv_value(value: &str) -> SecretString {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        // Double-quoted: unescape \n \r \t \\ \"
        // Note: Must handle \\ first, before other escape sequences
        SecretString::new(
            value[1..value.len() - 1]
                .replace("\\\\", "\x00") // Temporary placeholder for \\
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\x00", "\\"),
        ) // Restore \\ as single \
    } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        // Single-quoted: no escaping
        SecretString::new(value[1..value.len() - 1].to_string())
    } else {
        // Unquoted: use as-is
        SecretString::new(value.to_string())
    }
}

/// Parse dotenv format and extract KEY=VALUE pairs
pub fn parse_dotenv(content: &str) -> Result<HashMap<String, SecretString>> {
    let mut map = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Remove optional "export" prefix
        let line = line.strip_prefix("export ").unwrap_or(line).trim();

        // Find '=' separator
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();

            if is_valid_key_name(key) {
                map.insert(key.to_string(), parse_dotenv_value(value));
            }
        }
    }

    Ok(map)
}

// ============================================================================
// Dotenv Strict Validation
// ============================================================================

/// Strictly validate dotenv content for import.
///
/// Unlike `parse_dotenv` which silently skips invalid lines,
/// this function returns an error if any non-comment, non-empty line
/// is malformed (missing `=` separator or invalid key name).
/// Also returns an error if the content has no valid entries.
pub fn validate_dotenv_strict(content: &str) -> Result<()> {
    let mut entry_count = 0;

    for (line_num, line) in content.lines().enumerate() {
        if validate_dotenv_line(line.trim(), line_num + 1)? {
            entry_count += 1;
        }
    }

    if entry_count == 0 {
        return Err(Error::build_parse_error(
            "No valid entries found in dotenv file".to_string(),
        ));
    }

    Ok(())
}

/// Validate one trimmed line, reporting whether it declares an entry.
fn validate_dotenv_line(line: &str, line_number: usize) -> Result<bool> {
    // Empty lines and comments carry no entry
    if line.is_empty() || line.starts_with('#') {
        return Ok(false);
    }

    // Remove optional "export" prefix (same as parse_dotenv)
    let entry = line.strip_prefix("export ").unwrap_or(line).trim();

    // The line body is not included: it may carry a secret value the caller
    // mistyped without an `=`, and this error text can reach stderr/CI logs.
    let eq_pos = entry.find('=').ok_or_else(|| {
        Error::build_parse_error(format!("Line {}: missing '=' separator", line_number))
    })?;

    let key = entry[..eq_pos].trim();
    if !is_valid_key_name(key) {
        return Err(Error::build_parse_error(format!(
            "Line {}: invalid key name: '{}'",
            line_number, key
        )));
    }

    Ok(true)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "../../../tests/unit/internal/format_dotenv_test.rs"]
mod format_dotenv_test;
