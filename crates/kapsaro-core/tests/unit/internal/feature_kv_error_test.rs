// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for kv error construction.
//! Covers the user-facing message shape for missing keys and the code that identifies them.

use super::{build_key_not_found_error, is_key_not_found_error, normalize_key_not_found_error};
use crate::{Error, ErrorKind};

#[test]
fn test_build_key_not_found_error_names_the_key_and_carries_its_code() {
    let error = build_key_not_found_error("DATABASE_URL");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.format_user_message(), "Key 'DATABASE_URL' not found");
    assert!(is_key_not_found_error(&error, "DATABASE_URL"));
}

#[test]
fn test_is_key_not_found_error_rejects_another_key() {
    let error = build_key_not_found_error("DATABASE_URL");

    assert!(!is_key_not_found_error(&error, "API_TOKEN"));
}

#[test]
fn test_is_key_not_found_error_rejects_an_unmarked_look_alike_message() {
    let error = Error::build_invalid_operation_error("Key 'DATABASE_URL' not found");

    assert!(!is_key_not_found_error(&error, "DATABASE_URL"));
}

#[test]
fn test_is_key_not_found_error_rejects_unrelated_not_found_context() {
    let error = Error::build_not_found_error("Key 'DATABASE_URL' not found in default.kvenc");

    assert!(!is_key_not_found_error(&error, "DATABASE_URL"));
}

#[test]
fn test_normalize_key_not_found_error_preserves_matching_error_shape() {
    let error = build_key_not_found_error("DATABASE_URL");
    let mapped = normalize_key_not_found_error(error, "DATABASE_URL");

    assert_eq!(mapped.kind(), ErrorKind::InvalidOperation);
    assert_eq!(mapped.format_user_message(), "Key 'DATABASE_URL' not found");
    assert!(is_key_not_found_error(&mapped, "DATABASE_URL"));
}

#[test]
fn test_normalize_key_not_found_error_passes_unrelated_invalid_operation_through() {
    let error = Error::build_invalid_operation_error("recipient set mismatch");
    let mapped = normalize_key_not_found_error(error, "DATABASE_URL");

    assert_eq!(mapped.kind(), ErrorKind::InvalidOperation);
    assert_eq!(mapped.format_user_message(), "recipient set mismatch");
}
