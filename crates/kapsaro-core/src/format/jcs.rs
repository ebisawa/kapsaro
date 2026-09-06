// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JCS (JSON Canonicalization Scheme) normalization module.
//!
//! Implements RFC 8785 for deterministic JSON serialization.
//! This is required for consistent signature payloads.

use crate::format::FormatError;
use crate::Result;
use serde::Serialize;
use serde_json::Value;

mod serializer;

use serializer::IntegerOnly;

/// Normalize a JSON value to JCS bytes (RFC 8785).
/// This is used for signature computation.
pub fn normalize_to_bytes(value: &Value) -> Result<Vec<u8>> {
    normalize(value)
}

/// Normalize a JSON value to a JCS string (RFC 8785).
#[cfg(test)]
pub fn normalize_to_string(value: &Value) -> Result<String> {
    String::from_utf8(normalize(value)?).map_err(|e| {
        crate::Error::from(FormatError::build_parse_error_with_source(
            format!("JCS normalization failed: {}", e),
            e,
        ))
    })
}

/// Normalize any serializable value to JCS bytes.
pub fn normalize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(&IntegerOnly::new(value)).map_err(|e| {
        crate::Error::from(FormatError::build_parse_error_with_source(
            format!("JCS normalization failed: {}", e),
            e,
        ))
    })
}

#[cfg(test)]
#[path = "../../tests/unit/internal/format_jcs_test.rs"]
mod format_jcs_test;
