// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the workspace search.
//! Covers the reason a `.kapsaro` entry standing in the way is reported with.

use super::describe_rejected_workspace_dir;
use std::fs;
use tempfile::TempDir;

/// A link in that position is refused rather than followed, so the report names
/// the link. Naming the layout instead would send an operator looking for
/// directories that are already there behind it.
#[cfg(unix)]
#[test]
fn test_rejected_workspace_dir_names_a_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let complete = temp_dir.path().join("elsewhere");
    fs::create_dir_all(complete.join("members").join("active")).unwrap();
    fs::create_dir_all(complete.join("secrets")).unwrap();
    let current = temp_dir.path().join("checkout");
    fs::create_dir(&current).unwrap();
    symlink(&complete, current.join(".kapsaro")).unwrap();

    let error = describe_rejected_workspace_dir(&current).expect("the link must be reported");

    let message = error.format_user_message();
    assert!(message.contains("symlink"), "{message}");
    assert!(message.contains(".kapsaro"), "{message}");
}

/// An entry of another type holds no workspace, and saying so names what is
/// actually standing there.
#[test]
fn test_rejected_workspace_dir_names_an_entry_that_is_not_a_directory() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join(".kapsaro"), "not a workspace").unwrap();

    let error = describe_rejected_workspace_dir(temp_dir.path()).expect("the entry is reported");

    let message = error.format_user_message();
    assert!(message.contains("not a directory"), "{message}");
}

/// A real directory that the search turned away is missing part of the layout,
/// which is the one case the layout is the reason.
#[test]
fn test_rejected_workspace_dir_reports_an_incomplete_layout() {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join(".kapsaro")).unwrap();

    let error = describe_rejected_workspace_dir(temp_dir.path()).expect("the layout is reported");

    let message = error.format_user_message();
    assert!(
        message.contains("missing members/ or secrets/ directories"),
        "{message}"
    );
}

/// Nothing standing under that name is nothing to report: the caller goes on to
/// say no workspace was found from where the search started.
#[test]
fn test_rejected_workspace_dir_reports_nothing_when_the_name_is_free() {
    let temp_dir = TempDir::new().unwrap();

    assert!(describe_rejected_workspace_dir(temp_dir.path()).is_none());
}
