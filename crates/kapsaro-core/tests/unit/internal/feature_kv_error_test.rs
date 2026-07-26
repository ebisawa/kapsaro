// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for kv error construction.
//! Covers the user-facing message shape for missing keys.

use super::{is_key_not_found_error, normalize_key_not_found_error};
use crate::{Error, ErrorKind};

#[test]
fn test_normalize_key_not_found_error_preserves_matching_error_shape() {
    let error = Error::build_invalid_operation_error("Key 'DATABASE_URL' not found");
    let mapped = normalize_key_not_found_error(error, "DATABASE_URL");

    assert_eq!(mapped.kind(), ErrorKind::InvalidOperation);
    assert_eq!(mapped.format_user_message(), "Key 'DATABASE_URL' not found");
}

#[test]
fn test_normalize_key_not_found_error_passes_unrelated_invalid_operation_through() {
    let error = Error::build_invalid_operation_error("recipient set mismatch");
    let mapped = normalize_key_not_found_error(error, "DATABASE_URL");

    assert_eq!(mapped.kind(), ErrorKind::InvalidOperation);
    assert_eq!(mapped.format_user_message(), "recipient set mismatch");
}

#[test]
fn test_is_key_not_found_error_rejects_unrelated_not_found_context() {
    let error = Error::build_not_found_error("Key 'DATABASE_URL' not found in default.kvenc");

    assert!(!is_key_not_found_error(&error, "DATABASE_URL"));
}
