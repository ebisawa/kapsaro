// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Snapshot-based change detection for reviewed local state documents.
//! Pins that a replaced or rewritten file is refused at execution time.

#![cfg(unix)]

use super::{
    ensure_regular_file_matches_snapshot_at, load_optional_regular_file_snapshot_at,
    RegularFileSnapshot, TextFileSnapshot,
};
use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope, OpenDir};
use crate::ErrorKind;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

const SUBJECT: &str = "Reviewed document";

/// A text snapshot is addressed to a directory descriptor, so a test binds the
/// directory the way a command does before capturing what it holds.
fn open_dir(temp: &TempDir) -> Arc<OpenDir> {
    Arc::new(open_dir_nofollow(temp.path(), DirectoryScope::Generic).unwrap())
}

#[test]
fn test_snapshot_accepts_an_untouched_file_succeeds() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("doc.json"), "{}").unwrap();

    let result = with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)
            .map(|_| ())
    });

    assert!(result.is_ok(), "{:?}", result.err());
}

/// Replacing the file swaps the inode behind the name, which the held
/// descriptor still points at. Comparing content alone would miss it.
#[test]
fn test_snapshot_detects_a_file_replaced_by_a_new_inode() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("doc.json");
    fs::write(&path, "{}").unwrap();

    let error = with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        let replacement = temp.path().join("doc.json.new");
        fs::write(&replacement, "{}").unwrap();
        fs::rename(&replacement, &path).unwrap();
        ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)
            .map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(
        error
            .format_user_message()
            .contains("must be reviewed again"),
        "{}",
        error.format_user_message()
    );
}

/// A rewrite in place keeps the inode, so the change shows up in the metadata
/// rather than the identity.
#[test]
fn test_snapshot_detects_a_file_rewritten_in_place() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("doc.json");
    fs::write(&path, "{}").unwrap();

    let error = with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        fs::write(&path, "{\"changed\": true}").unwrap();
        ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)
            .map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
}

/// A document that was absent at review time must still be absent, or the
/// operation would act on something the operator never saw.
#[test]
fn test_snapshot_detects_a_file_created_after_review() {
    let temp = TempDir::new().unwrap();

    let error = with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        fs::write(temp.path().join("doc.json"), "{}").unwrap();
        ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)
            .map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
}

#[test]
fn test_snapshot_detects_a_file_removed_after_review() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("doc.json");
    fs::write(&path, "{}").unwrap();

    let error = with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        fs::remove_file(&path).unwrap();
        ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)
            .map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
}

#[test]
fn test_snapshot_accepts_an_absence_that_persists_succeeds() {
    let temp = TempDir::new().unwrap();

    let result = with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)
            .map(|_| ())
    });

    assert!(result.is_ok(), "{:?}", result.err());
}

/// Raw bytes are part of the snapshot even when every filesystem attribute is
/// identical, so metadata spoofing cannot make different content acceptable.
#[test]
fn test_snapshot_rejects_different_bytes_with_identical_identity_and_metadata() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("doc.json"), "reviewed-content").unwrap();

    with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?
            .expect("the reviewed snapshot exists");
        let mut current = load_optional_regular_file_snapshot_at(dir, "doc.json")?
            .expect("the current snapshot exists");
        current.raw_bytes = b"different-bytes".to_vec();

        assert!(!reviewed.matches(&current)?);
        Ok(())
    })
    .unwrap();
}

/// Snapshot diagnostics report only the byte count, never the document bytes.
#[test]
fn test_snapshot_debug_redacts_raw_bytes() {
    const SENTINEL: &str = "raw-document-sentinel";
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("doc.json"), SENTINEL).unwrap();

    let snapshot: RegularFileSnapshot = with_locked_workspace_dir(temp.path(), |dir| {
        load_optional_regular_file_snapshot_at(dir, "doc.json")
            .map(|snapshot| snapshot.expect("the snapshot exists"))
    })
    .unwrap();
    let debug = format!("{snapshot:?}");

    assert!(!debug.contains(SENTINEL), "{debug}");
    assert!(
        debug.contains(&format!("{} bytes", SENTINEL.len())),
        "{debug}"
    );
}

/// A caller that goes on to delete the reviewed document unlinks it by name,
/// and the name can point at a different inode by then. The confirmation hands
/// back the descriptor so that last step can be taken on the entry it accepted.
#[test]
fn test_snapshot_confirmation_returns_the_entry_it_accepted() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("doc.json"), "{}").unwrap();

    with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        let confirmed =
            ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)?
                .expect("a reviewed document is handed back");

        assert!(confirmed.still_holds(dir, "doc.json")?);
        Ok(())
    })
    .unwrap();
}

/// Replacing the name after the confirmation swaps the inode behind it. The
/// held descriptor still points at the reviewed file, so the caller can tell
/// that the entry it is about to remove is no longer the one it approved.
#[test]
fn test_snapshot_reports_a_name_repointed_after_the_confirmation() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("doc.json");
    fs::write(&path, "{}").unwrap();

    with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        let confirmed =
            ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)?
                .expect("a reviewed document is handed back");

        let replacement = temp.path().join("doc.json.new");
        fs::write(&replacement, "{}").unwrap();
        fs::rename(&replacement, &path).unwrap();

        assert!(!confirmed.still_holds(dir, "doc.json")?);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_snapshot_reports_a_name_removed_after_the_confirmation() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("doc.json");
    fs::write(&path, "{}").unwrap();

    with_locked_workspace_dir(temp.path(), |dir| {
        let reviewed = load_optional_regular_file_snapshot_at(dir, "doc.json")?;
        let confirmed =
            ensure_regular_file_matches_snapshot_at(dir, "doc.json", reviewed.as_ref(), SUBJECT)?
                .expect("a reviewed document is handed back");

        fs::remove_file(&path).unwrap();

        assert!(!confirmed.still_holds(dir, "doc.json")?);
        Ok(())
    })
    .unwrap();
}

/// A name repointed at a different file holding the same bytes is not the file
/// that was reviewed, and only the descriptor kept from review time says so.
#[test]
fn test_text_snapshot_reports_a_name_repointed_at_an_identical_file() {
    let temp = TempDir::new().unwrap();
    let reviewed_path = temp.path().join("doc.kvenc");
    fs::write(&reviewed_path, "same bytes").unwrap();
    let snapshot =
        TextFileSnapshot::capture_at(open_dir(&temp), "doc.kvenc", 1024, SUBJECT).unwrap();

    let twin = temp.path().join("twin.kvenc");
    fs::write(&twin, "same bytes").unwrap();
    fs::rename(&twin, &reviewed_path).unwrap();

    let holds = with_locked_workspace_dir(temp.path(), |dir| snapshot.still_holds_in(dir)).unwrap();

    assert!(
        !holds,
        "matching bytes must not stand in for the reviewed inode"
    );
}

/// The very file that was reviewed is still recognised as itself.
#[test]
fn test_text_snapshot_accepts_the_file_it_reviewed() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("doc.kvenc"), "content").unwrap();
    let snapshot =
        TextFileSnapshot::capture_at(open_dir(&temp), "doc.kvenc", 1024, SUBJECT).unwrap();

    let holds = with_locked_workspace_dir(temp.path(), |dir| snapshot.still_holds_in(dir)).unwrap();

    assert!(holds);
}

/// A review that captured an absence has no inode to bind to, so the identity
/// check leaves the answer to the content comparison beside it.
#[test]
fn test_text_snapshot_of_an_absent_file_claims_no_identity() {
    let temp = TempDir::new().unwrap();
    let snapshot =
        TextFileSnapshot::capture_at(open_dir(&temp), "missing.kvenc", 1024, SUBJECT).unwrap();

    let holds = with_locked_workspace_dir(temp.path(), |dir| snapshot.still_holds_in(dir)).unwrap();

    assert!(holds);
}
