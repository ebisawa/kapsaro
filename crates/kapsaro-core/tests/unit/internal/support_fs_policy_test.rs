// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Directory creation policy for paths addressed by name.
//! Pins the descriptor chain each level is made on and the answers an inspection may give.

use super::{ensure_real_directory_tree, is_real_dir, run_after_next_level_created, DirectoryKind};
#[cfg(unix)]
use crate::support::fs::test_umask::{isolated_umask_test, with_umask};
#[cfg(unix)]
use crate::test_utils::permission_denial_can_be_staged;
use crate::ErrorKind;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_ensure_real_directory_tree_creates_every_missing_level() {
    let temp = TempDir::new().unwrap();
    let deep = temp.path().join("a").join("b").join("c");

    ensure_real_directory_tree(&deep, DirectoryKind::General).unwrap();

    assert!(deep.is_dir());
}

/// Each level is made on the descriptor of the level above it. Creating them by
/// full path would resolve the earlier ones again, so a level replaced by a
/// symlink between two steps would carry the rest of the tree wherever it points.
#[cfg(unix)]
#[test]
fn test_ensure_real_directory_tree_keeps_later_levels_below_the_directory_it_opened() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let first = temp.path().join("first");
    let moved = temp.path().join("first.real");
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();

    let swap = {
        let first = first.clone();
        let moved = moved.clone();
        let outside = outside.clone();
        move || {
            fs::rename(&first, &moved).unwrap();
            symlink(&outside, &first).unwrap();
        }
    };
    run_after_next_level_created(swap);

    ensure_real_directory_tree(&first.join("second"), DirectoryKind::General).unwrap();

    assert!(
        moved.join("second").is_dir(),
        "the second level must land inside the directory the first step opened"
    );
    assert!(
        !outside.join("second").exists(),
        "creation must not follow a level replaced after it was made"
    );
}

#[cfg(unix)]
#[test]
fn test_ensure_real_directory_tree_refuses_a_symlinked_ancestor() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let real = temp.path().join("outside");
    let linked = temp.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();

    let error =
        ensure_real_directory_tree(&linked.join("nested"), DirectoryKind::Workspace).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(
        error.format_user_message().contains("symlink"),
        "{}",
        error.format_user_message()
    );
    assert!(!real.join("nested").exists());
}

#[test]
fn test_is_real_dir_accepts_a_directory() {
    let temp = TempDir::new().unwrap();

    assert!(is_real_dir(temp.path()).unwrap());
}

#[test]
fn test_is_real_dir_reports_a_missing_path_as_absent() {
    let temp = TempDir::new().unwrap();

    assert!(!is_real_dir(&temp.path().join("missing")).unwrap());
}

#[test]
fn test_is_real_dir_reports_a_regular_file_as_not_a_directory() {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("file");
    fs::write(&file, "payload").unwrap();

    assert!(!is_real_dir(&file).unwrap());
}

#[cfg(unix)]
#[test]
fn test_is_real_dir_reports_a_symlinked_directory_as_not_a_directory() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    let alias = temp.path().join("alias");
    fs::create_dir(&real).unwrap();
    symlink(&real, &alias).unwrap();

    assert!(!is_real_dir(&alias).unwrap());
}

/// An inspection that could not answer is not an absence. Reporting it as one
/// would send the caller on to create a directory it was never allowed to see,
/// and the failure that followed would name the creation rather than the denial.
#[cfg(unix)]
#[test]
fn test_is_real_dir_propagates_a_denied_inspection() {
    use std::os::unix::fs::PermissionsExt;

    if !permission_denial_can_be_staged("test_is_real_dir_propagates_a_denied_inspection") {
        return;
    }

    let temp = TempDir::new().unwrap();
    let outer = temp.path().join("outer");
    let inner = outer.join("inner");
    fs::create_dir_all(&inner).unwrap();
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o000)).unwrap();
    let _restored = RestoredMode(outer);

    let error = is_real_dir(&inner).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Io);
    assert!(
        error.format_user_message().contains("Failed to inspect"),
        "{}",
        error.format_user_message()
    );
}

/// Put a directory back within reach of its owner however the test ends.
///
/// A denial is staged by taking every bit off a directory, and an assertion
/// that panics in between would otherwise leave it that way: the temporary
/// directory holding it cannot be removed, and the test that failed is joined
/// by a cleanup failure that says nothing about it.
#[cfg(unix)]
struct RestoredMode(std::path::PathBuf);

#[cfg(unix)]
impl Drop for RestoredMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;

        // A panic here would run while the test's own panic is unwinding and
        // abort the process, hiding the failure this guard exists to report.
        // A restore that did not take shows up as the temporary directory
        // refusing to be removed.
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
    }
}

isolated_umask_test! {
    /// The umask decides the mode of a workspace directory, which is shared
    /// through git. Pinning it to 0700 would make the tree unreadable to
    /// everyone else and change mode on every machine that checks it out.
    #[cfg(unix)]
    fn test_ensure_real_directory_tree_leaves_the_mode_to_the_umask() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let created = temp.path().join("shared");

        with_umask(0o022, || {
            ensure_real_directory_tree(&created, DirectoryKind::Workspace).unwrap();
        });

        let mode = fs::metadata(&created).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
}
