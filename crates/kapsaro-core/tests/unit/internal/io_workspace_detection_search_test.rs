// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the workspace search.
//! Covers the reason a `.kapsaro` entry standing in the way is reported with.

use super::{build_rejected_workspace_dir_error, find_git_root};
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

    let error = build_rejected_workspace_dir_error(&current).expect("the link must be reported");

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

    let error = build_rejected_workspace_dir_error(temp_dir.path()).expect("the entry is reported");

    let message = error.format_user_message();
    assert!(message.contains("not a directory"), "{message}");
}

/// A real directory that the search turned away is missing part of the layout,
/// which is the one case the layout is the reason.
#[test]
fn test_rejected_workspace_dir_reports_an_incomplete_layout() {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join(".kapsaro")).unwrap();

    let error =
        build_rejected_workspace_dir_error(temp_dir.path()).expect("the layout is reported");

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

    assert!(build_rejected_workspace_dir_error(temp_dir.path()).is_none());
}

/// A lookup that was refused is not an absence. Reading it as one would carry
/// the search past the level it was never allowed to see and settle on whatever
/// repository stands above it.
#[cfg(unix)]
#[test]
fn test_find_git_root_propagates_a_denied_lookup() {
    use crate::test_utils::permission_denial_can_be_staged;
    use std::os::unix::fs::PermissionsExt;

    if !permission_denial_can_be_staged("test_find_git_root_propagates_a_denied_lookup") {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let checkout = temp_dir.path().join("checkout");
    fs::create_dir(&checkout).unwrap();
    fs::set_permissions(&checkout, fs::Permissions::from_mode(0o000)).unwrap();
    let _restored = RestoredMode(checkout.clone());

    let error = find_git_root(&checkout).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Io);
}

/// A worktree records `.git` as a file, so any entry standing under that name
/// marks the repository root.
#[test]
fn test_find_git_root_accepts_a_git_file() {
    let temp_dir = TempDir::new().unwrap();
    let checkout = temp_dir.path().join("checkout");
    fs::create_dir(&checkout).unwrap();
    fs::write(checkout.join(".git"), "gitdir: /elsewhere\n").unwrap();

    let root = find_git_root(&checkout).unwrap();

    assert_eq!(root, Some(checkout.canonicalize().unwrap()));
}

/// Put a directory back within reach of its owner however the test ends, so a
/// failed assertion is not joined by a cleanup that cannot remove the tree.
#[cfg(unix)]
struct RestoredMode(std::path::PathBuf);

#[cfg(unix)]
impl Drop for RestoredMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;

        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
    }
}
