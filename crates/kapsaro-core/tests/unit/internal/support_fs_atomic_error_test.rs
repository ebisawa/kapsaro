// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error-path unit tests for support/fs/atomic module.
//!
//! Complements support_fs_atomic_test.rs (happy paths) by exercising
//! failure branches of save_bytes / save_json / save_text.

use crate::support::fs::atomic::{save_bytes, save_json, save_text};
#[cfg(unix)]
use crate::test_utils::permission_denial_can_be_staged;
use kapsaro_core::ErrorKind;
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

/// Every path-addressed save makes the parent it needs before it stages
/// anything, so a name already taken by a file is reported as the directory
/// that could not be made rather than as a failure of the write behind it.
///
/// The two entry points are checked together because they answer as one: a
/// caller choosing between bytes and text must not have to know that one of
/// them creates the parent and the other refuses.
#[test]
fn test_saving_below_a_parent_that_is_a_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let file_as_parent = temp_dir.path().join("plain_file");
    fs::write(&file_as_parent, b"blocker").unwrap();

    let errors = [
        save_bytes(&file_as_parent.join("child.bin"), b"payload")
            .expect_err("a file cannot become the parent directory of a write"),
        save_text(&file_as_parent.join("child.txt"), "payload")
            .expect_err("a file cannot become the parent directory of a write"),
    ];

    for error in errors {
        assert_eq!(error.kind(), ErrorKind::Io);
        assert!(
            error
                .format_user_message()
                .contains("Failed to create directory"),
            "unexpected message: {}",
            error.format_user_message()
        );
    }
}

/// A write must stop when the parent cannot be told apart from a symlink.
///
/// Treating an inspection failure as "not a symlink" lets the write proceed
/// against a parent whose identity was never established.
#[cfg(unix)]
#[test]
fn test_save_bytes_propagates_an_unreadable_parent_instead_of_writing() {
    use std::os::unix::fs::PermissionsExt;

    if !permission_denial_can_be_staged(
        "test_save_bytes_propagates_an_unreadable_parent_instead_of_writing",
    ) {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let outer = temp_dir.path().join("outer");
    let parent = outer.join("inner");
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o000)).unwrap();

    let err = save_bytes(&parent.join("child.bin"), b"payload")
        .expect_err("an unreadable parent must not be treated as a plain directory");

    fs::set_permissions(&outer, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(err.kind(), ErrorKind::Io);
    assert!(
        err.format_user_message().contains("Failed to inspect"),
        "the failure must name the inspection that could not answer: {}",
        err.format_user_message()
    );
}

#[test]
fn test_save_json_serialization_failure_maps_to_parse_error() {
    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("bad.json");

    let err = save_json(&target, &AlwaysFailSerialize).expect_err("custom Serialize always fails");
    assert_eq!(err.kind(), ErrorKind::Parse);
    assert!(
        err.format_user_message()
            .contains("JSON serialization failed"),
        "unexpected message: {}",
        err.format_user_message()
    );
    assert!(
        err.format_user_message()
            .contains("forced serialization failure"),
        "error message should surface the underlying reason: {}",
        err.format_user_message()
    );
    assert!(
        !target.exists(),
        "target file must not be created on serialization failure"
    );
}
