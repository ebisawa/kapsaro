// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for app/errors.rs helpers.

use crate::app::errors::{
    build_default_kv_file_not_found_error, build_invalid_trust_store_error,
    build_kv_key_not_found_error, serialize_to_json_value,
};
use crate::Error;
use serde::{Serialize, Serializer};
use std::path::Path;

#[test]
fn test_build_kv_key_not_found_error_rewrites_quoted_pattern() {
    let err = Error::build_invalid_operation_error("Key 'foo' not found");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    match wrapped {
        Error::NotFound { message } => {
            assert!(message.contains("Key 'foo' not found"));
            assert!(message.contains("x.kvenc"));
        }
        other => panic!("expected Error::NotFound, got {:?}", other),
    }
}

#[test]
fn test_build_kv_key_not_found_error_rewrites_unquoted_pattern() {
    let err = Error::build_invalid_operation_error("Key not found: foo");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    match wrapped {
        Error::NotFound { message } => {
            assert!(message.contains("Key not found: foo"));
            assert!(message.contains("x.kvenc"));
        }
        other => panic!("expected Error::NotFound, got {:?}", other),
    }
}

#[test]
fn test_build_kv_key_not_found_error_passthrough_for_unrelated_operation() {
    let err = Error::build_invalid_operation_error("something else entirely");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    match wrapped {
        Error::InvalidOperation { message } => {
            assert_eq!(message, "something else entirely");
        }
        other => panic!("expected Error::InvalidOperation, got {:?}", other),
    }
}

#[test]
fn test_build_kv_key_not_found_error_augments_existing_not_found() {
    let err = Error::build_not_found_error("entry foo not found in document");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    match wrapped {
        Error::NotFound { message } => {
            assert!(message.contains("entry foo not found"));
            assert!(message.contains("x.kvenc"));
        }
        other => panic!("expected Error::NotFound, got {:?}", other),
    }
}

#[test]
fn test_build_kv_key_not_found_error_passthrough_for_unrelated_not_found() {
    let err = Error::build_not_found_error("member alice missing");
    let wrapped = build_kv_key_not_found_error(err, Path::new("/tmp/x.kvenc"), "foo");
    match wrapped {
        Error::NotFound { message } => {
            assert_eq!(message, "member alice missing");
        }
        other => panic!("expected Error::NotFound, got {:?}", other),
    }
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
    match err {
        Error::Parse { message, source } => {
            assert!(message.contains("Failed to serialize member document"));
            assert!(message.contains("forced failure"));
            assert!(source.is_some());
        }
        other => panic!("expected Error::Parse, got {:?}", other),
    }
}

#[test]
fn test_build_default_kv_file_not_found_error_includes_path_and_hint() {
    let err = build_default_kv_file_not_found_error(Path::new("/tmp/.secretenv/kv/default.kvenc"));
    match err {
        Error::NotFound { message } => {
            assert!(message.contains("Default kv file not found"));
            assert!(message.contains("default.kvenc"));
            assert!(message.contains("'secretenv set'"));
        }
        other => panic!("expected Error::NotFound, got {:?}", other),
    }
}

#[test]
fn test_build_invalid_trust_store_error_uses_reset_rule() {
    let inner = Error::build_parse_error("bad JSON");
    let err = build_invalid_trust_store_error(Path::new("/tmp/.secretenv/trust_store.json"), inner);
    match err {
        Error::Verify { rule, message } => {
            assert_eq!(rule, "E_TRUST_STORE_RESET_REQUIRED");
            assert!(message.contains("trust_store.json"));
            assert!(message.contains("bad JSON"));
        }
        other => panic!("expected Error::Verify, got {:?}", other),
    }
}
