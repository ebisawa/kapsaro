// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guards on the directory a reviewed text file is bound to.
//! Pins that checks and writes only run through the directory that was reviewed.

#![cfg(unix)]

use std::fs;
use std::sync::Arc;

use tempfile::TempDir;

use super::ReviewedTextFile;
use crate::support::fs::relative::{
    open_dir_nofollow, set_pre_publish_hook, DirectoryScope, OpenDir,
};

const SUBJECT: &str = "Reviewed document";

fn open_dir(path: &std::path::Path) -> Arc<OpenDir> {
    Arc::new(open_dir_nofollow(path, DirectoryScope::Generic).unwrap())
}

/// Two directories holding an entry of the same name, so a test can hand a
/// check the wrong one on purpose.
fn build_two_trees(
    temp: &TempDir,
    content: &str,
    other_content: &str,
) -> (Arc<OpenDir>, Arc<OpenDir>) {
    let reviewed = temp.path().join("reviewed");
    let other = temp.path().join("other");
    fs::create_dir(&reviewed).unwrap();
    fs::create_dir(&other).unwrap();
    fs::write(reviewed.join("doc.json"), content).unwrap();
    fs::write(other.join("doc.json"), other_content).unwrap();
    (open_dir(&reviewed), open_dir(&other))
}

/// A check addressed to another directory would answer about an entry nobody
/// reviewed, so it is refused rather than answered.
#[test]
fn test_identity_check_refuses_a_directory_other_than_the_reviewed_one() {
    let temp = TempDir::new().unwrap();
    let (reviewed_dir, other_dir) = build_two_trees(&temp, "reviewed", "reviewed");
    let reviewed =
        ReviewedTextFile::load_existing_at(reviewed_dir, "doc.json", SUBJECT, 1024).unwrap();

    let error = reviewed
        .ensure_identity_and_content_current_at(other_dir.as_ref())
        .unwrap_err();

    assert!(
        error
            .format_user_message()
            .contains("was reviewed under another directory"),
        "{}",
        error.format_user_message()
    );
}

/// The same guard covers the write: the replacement has to land in the tree the
/// review read from.
#[test]
fn test_replacement_refuses_a_directory_other_than_the_reviewed_one() {
    let temp = TempDir::new().unwrap();
    let (reviewed_dir, other_dir) = build_two_trees(&temp, "reviewed", "reviewed");
    let reviewed =
        ReviewedTextFile::load_existing_at(reviewed_dir, "doc.json", SUBJECT, 1024).unwrap();

    let error = reviewed
        .save_replacement_at(other_dir.as_ref(), "rewritten")
        .unwrap_err();

    assert!(
        error
            .format_user_message()
            .contains("was reviewed under another directory"),
        "{}",
        error.format_user_message()
    );
    assert_eq!(
        fs::read_to_string(temp.path().join("other").join("doc.json")).unwrap(),
        "reviewed"
    );
}

/// The target can change while its replacement is being staged. The final
/// precondition catches even a same-bytes inode replacement before rename.
#[test]
fn test_replacement_rechecks_identity_immediately_before_publish() {
    let temp = TempDir::new().unwrap();
    let directory = temp.path().join("reviewed");
    fs::create_dir(&directory).unwrap();
    let target = directory.join("doc.json");
    fs::write(&target, "reviewed").unwrap();
    let reviewed_dir = open_dir(&directory);
    let reviewed =
        ReviewedTextFile::load_existing_at(Arc::clone(&reviewed_dir), "doc.json", SUBJECT, 1024)
            .unwrap();

    let replacement = directory.join("replacement.json");
    fs::write(&replacement, "reviewed").unwrap();
    set_pre_publish_hook(move || fs::rename(replacement, target).unwrap());

    let error = reviewed
        .save_replacement_if_current_at(reviewed_dir.as_ref(), "rewritten")
        .unwrap_err();

    assert!(
        error.format_user_message().contains("changed since review"),
        "{}",
        error.format_user_message()
    );
    assert_eq!(
        fs::read_to_string(directory.join("doc.json")).unwrap(),
        "reviewed"
    );
}

/// The check runs against the directory that was reviewed, whatever the path
/// naming it points at by then.
#[test]
fn test_identity_check_accepts_the_directory_it_was_reviewed_under() {
    let temp = TempDir::new().unwrap();
    let (reviewed_dir, _other_dir) = build_two_trees(&temp, "reviewed", "other");
    let reviewed =
        ReviewedTextFile::load_existing_at(Arc::clone(&reviewed_dir), "doc.json", SUBJECT, 1024)
            .unwrap();

    reviewed
        .ensure_identity_and_content_current_at(reviewed_dir.as_ref())
        .unwrap();
}

/// Two reviews of the same entry name in two trees saw two different files, and
/// the bytes alone cannot tell them apart.
#[test]
fn test_reviewed_state_comparison_separates_two_trees_holding_the_same_bytes() {
    let temp = TempDir::new().unwrap();
    let (reviewed_dir, other_dir) = build_two_trees(&temp, "same bytes", "same bytes");
    let reviewed =
        ReviewedTextFile::load_existing_at(reviewed_dir, "doc.json", SUBJECT, 1024).unwrap();
    let elsewhere =
        ReviewedTextFile::load_existing_at(other_dir, "doc.json", SUBJECT, 1024).unwrap();

    assert!(!reviewed.matches_reviewed_state(&elsewhere).unwrap());
}

/// Two reads of the one entry are the same reviewed state.
#[test]
fn test_reviewed_state_comparison_accepts_two_reads_of_one_entry() {
    let temp = TempDir::new().unwrap();
    let (reviewed_dir, _other_dir) = build_two_trees(&temp, "same bytes", "other");
    let first =
        ReviewedTextFile::load_existing_at(Arc::clone(&reviewed_dir), "doc.json", SUBJECT, 1024)
            .unwrap();
    let second =
        ReviewedTextFile::load_existing_at(reviewed_dir, "doc.json", SUBJECT, 1024).unwrap();

    assert!(first.matches_reviewed_state(&second).unwrap());
}
