// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for app/errors.rs helpers.

use crate::app::errors::{
    build_default_kv_file_not_found_error, build_invalid_trust_store_error,
    build_kv_key_not_found_error, serialize_to_json_value,
};
use crate::{Error, ErrorKind};
use serde::{Serialize, Serializer};
use std::path::Path;

#[test]
fn test_build_kv_key_not_found_error_rewrites_quoted_pattern() {
    let err = Error::build_invalid_operation_error("Key 'foo' not found");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    assert_eq!(wrapped.kind(), ErrorKind::NotFound);
    assert!(wrapped
        .format_user_message()
        .contains("Key 'foo' not found"));
    assert!(wrapped.format_user_message().contains("x.kvenc"));
}

#[test]
fn test_build_kv_key_not_found_error_rewrites_unquoted_pattern() {
    let err = Error::build_invalid_operation_error("Key not found: foo");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    assert_eq!(wrapped.kind(), ErrorKind::NotFound);
    assert!(wrapped.format_user_message().contains("Key not found: foo"));
    assert!(wrapped.format_user_message().contains("x.kvenc"));
}

#[test]
fn test_build_kv_key_not_found_error_passthrough_for_unrelated_operation() {
    let err = Error::build_invalid_operation_error("something else entirely");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    assert_eq!(wrapped.kind(), ErrorKind::InvalidOperation);
    assert_eq!(wrapped.format_user_message(), "something else entirely");
}

#[test]
fn test_build_kv_key_not_found_error_augments_existing_not_found() {
    let err = Error::build_not_found_error("entry foo not found in document");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    assert_eq!(wrapped.kind(), ErrorKind::NotFound);
    assert!(wrapped
        .format_user_message()
        .contains("entry foo not found"));
    assert!(wrapped.format_user_message().contains("x.kvenc"));
}

#[test]
fn test_build_kv_key_not_found_error_passthrough_for_unrelated_not_found() {
    let err = Error::build_not_found_error("member alice missing");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    assert_eq!(wrapped.kind(), ErrorKind::NotFound);
    assert_eq!(wrapped.format_user_message(), "member alice missing");
}

#[test]
fn test_serialize_to_json_value_serializes_value() {
    let value = serde_json::json!({"name": "alice", "n": 42});
    let converted = serialize_to_json_value(&value).unwrap();
    assert_eq!(converted, value);
}

#[test]
fn test_serialize_to_json_value_failure_maps_to_parse_error() {
    struct AlwaysFailSerialize;
    impl Serialize for AlwaysFailSerialize {
        fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("forced failure"))
        }
    }

    let err = serialize_to_json_value(&AlwaysFailSerialize).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Parse);
    assert!(err
        .format_user_message()
        .contains("Failed to serialize member document"));
    assert!(err.format_user_message().contains("forced failure"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn test_build_default_kv_file_not_found_error_includes_path_and_hint() {
    let err = build_default_kv_file_not_found_error(Path::new("/tmp/.secretenv/kv/default.kvenc"));
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert!(err
        .format_user_message()
        .contains("Default kv file not found"));
    assert!(err.format_user_message().contains("default.kvenc"));
    assert!(err.format_user_message().contains("'secretenv set'"));
}

#[test]
fn test_build_invalid_trust_store_error_uses_reset_rule() {
    let inner = Error::build_parse_error("bad JSON");
    let err = build_invalid_trust_store_error(Path::new("/tmp/.secretenv/trust_store.json"), inner);
    assert_eq!(err.kind(), ErrorKind::Verify);
    assert_eq!(
        err.verification_rule(),
        Some("E_TRUST_STORE_RESET_REQUIRED")
    );
    assert!(err.format_user_message().contains("trust_store.json"));
    assert!(err.format_user_message().contains("bad JSON"));
}
