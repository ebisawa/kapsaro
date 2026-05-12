// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Dotenv format parser
//!
//! Provides functions to parse dotenv-style KEY=VALUE pairs with support for
//! quoted values and escape sequences.

use crate::support::secret::SecretString;
use crate::Result;
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
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Remove optional "export" prefix (same as parse_dotenv)
        let original_line = line;
        let line = line.strip_prefix("export ").unwrap_or(line).trim();

        // Must have '=' separator
        let eq_pos = line.find('=').ok_or_else(|| crate::Error::Parse {
            message: format!(
                "Line {}: missing '=' separator: {}",
                line_num + 1,
                original_line
            ),
            source: None,
        })?;

        // Key must be valid
        let key = line[..eq_pos].trim();
        if !is_valid_key_name(key) {
            return Err(crate::Error::Parse {
                message: format!("Line {}: invalid key name: '{}'", line_num + 1, key),
                source: None,
            });
        }

        entry_count += 1;
    }

    if entry_count == 0 {
        return Err(crate::Error::Parse {
            message: "No valid entries found in dotenv file".to_string(),
            source: None,
        });
    }

    Ok(())
}

// ============================================================================
// Dotenv Serialization
// ============================================================================

/// Quote a value for dotenv format if needed.
///
/// Serialization rules:
/// - Unquoted: if value contains no special characters
/// - Double-quoted: if value contains special characters, with escaping
/// - Single-quoted: not used in serialization (only for parsing)
fn quote_value(value: &str) -> String {
    // Check if value needs quoting (contains special characters or is empty)
    let needs_quoting = value.is_empty()
        || value.contains(' ')
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('\t')
        || value.contains('"')
        || value.contains('\'')
        || value.contains('\\')
        || value.contains('#')
        || value.contains('=');

    if !needs_quoting {
        return value.to_string();
    }

    // Double-quote with escaping
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(ch),
        }
    }
    result.push('"');
    result
}

/// Build a dotenv format string from a HashMap.
///
/// Keys are sorted for deterministic output.
/// Values are quoted if they contain special characters.
pub fn build_dotenv_string<V>(map: &HashMap<String, V>) -> String
where
    V: AsRef<str>,
{
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut result = String::new();
    for (key, value) in entries {
        result.push_str(key);
        result.push('=');
        result.push_str(&quote_value(value.as_ref()));
        result.push('\n');
    }
    result
}

// ============================================================================
// Tests
// ============================================================================
