// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error-path unit tests for support/fs/atomic module.
//!
//! Complements support_fs_atomic_test.rs (happy paths) by exercising
//! failure branches of save_bytes / save_json / save_text.

use secretenv::support::fs::atomic::{save_bytes, save_json, save_text, save_text_restricted};
use secretenv::Error;
use serde::{Serialize, Serializer};
use std::fs;
use tempfile::TempDir;

/// Serialize impl that always fails, used to exercise save_json's
/// serialization-error branch without relying on JSON-specific rejection rules.
struct AlwaysFailSerialize;

impl Serialize for AlwaysFailSerialize {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(serde::ser::Error::custom("forced serialization failure"))
    }
}

#[test]
fn test_save_bytes_parent_is_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let file_as_parent = temp_dir.path().join("plain_file");
    fs::write(&file_as_parent, b"blocker").unwrap();

    let target = file_as_parent.join("child.bin");
    let err = save_bytes(&target, b"payload").expect_err("parent is a file, expected error");

    match err {
        Error::Io { message, .. } => {
            assert!(
                message.contains("Failed to create temp file"),
                "unexpected message: {}",
                message
            );
        }
        other => panic!("expected Error::Io, got {:?}", other),
    }
}

#[test]
fn test_save_bytes_parent_missing_fails() {
    let temp_dir = TempDir::new().unwrap();
    let missing_parent = temp_dir.path().join("does_not_exist");
    let target = missing_parent.join("child.bin");

    let err = save_bytes(&target, b"payload").expect_err("missing parent, expected error");
    assert!(matches!(err, Error::Io { .. }));
}

#[test]
fn test_save_text_parent_is_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let file_as_parent = temp_dir.path().join("plain_file");
    fs::write(&file_as_parent, b"blocker").unwrap();

    let target = file_as_parent.join("child.txt");
    let err = save_text(&target, "payload").expect_err("parent is a file, expected error");

    match err {
        Error::Io { message, .. } => {
            assert!(
                message.contains("Failed to create directory"),
                "unexpected message: {}",
                message
            );
        }
        other => panic!("expected Error::Io, got {:?}", other),
    }
}

#[test]
fn test_save_text_restricted_parent_is_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let file_as_parent = temp_dir.path().join("plain_file");
    fs::write(&file_as_parent, b"blocker").unwrap();

    let target = file_as_parent.join("child.txt");
    let err =
        save_text_restricted(&target, "payload").expect_err("parent is a file, expected error");
    assert!(matches!(err, Error::Io { .. }));
}

#[test]
fn test_save_json_serialization_failure_maps_to_parse_error() {
    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("bad.json");

    let err = save_json(&target, &AlwaysFailSerialize).expect_err("custom Serialize always fails");
    match err {
        Error::Parse { message, .. } => {
            assert!(
                message.contains("JSON serialization failed"),
                "unexpected message: {}",
                message
            );
            assert!(
                message.contains("forced serialization failure"),
                "error message should surface the underlying reason: {}",
                message
            );
        }
        other => panic!("expected Error::Parse, got {:?}", other),
    }
    assert!(
        !target.exists(),
        "target file must not be created on serialization failure"
    );
}
