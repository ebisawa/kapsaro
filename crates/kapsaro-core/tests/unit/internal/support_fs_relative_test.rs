// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for directory-fd-relative filesystem helpers.
//! Covers child-name validation and directory-bound read/write/remove.

use super::{
    classify_missing_child_dir, create_child_dir_restricted_at, create_text_noreplace_at,
    ensure_child_dir_at, ensure_child_dir_restricted_at, ensure_text_file_content_matches_at,
    fail_next_child_dir_creation_at, fail_next_parent_sync, file_exists_at, is_write_staging_name,
    list_child_entries_at, load_text_with_limit_at, open_child_dir, open_child_dir_following,
    open_dir_following, open_dir_nofollow, open_optional_child_dir, open_scanned_child_dir,
    read_directory_entry_error, regular_file_exists_at, remove_empty_child_dir_if_exists_at,
    remove_file_at, remove_file_if_exists_at, rename_child_noreplace_unsynced_at, save_text_at,
    save_text_restricted_at, scan_child_entries_at, scan_one_child, vanish_next_scanned_child,
    ChildDirectoryCreationStep, ChildName, ChildType, DirectoryFd, DirectoryScope, RemovedEntry,
    ScanBudget,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
use crate::support::fs::lock::with_exclusive_locked_directory;
#[cfg(unix)]
use crate::support::fs::test_umask::{isolated_umask_test, with_restrictive_umask};
use crate::support::limits::MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH;
use crate::support::warning::LocalStateWarningGuard;
#[cfg(unix)]
use crate::test_utils::permission_denial_can_be_staged;
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_open_dir_following_rejects_non_directory() {
    let temp_dir = TempDir::new().unwrap();
    let file = temp_dir.path().join("file");
    fs::write(&file, "payload").unwrap();

    let error = open_dir_following(&file, DirectoryScope::LocalState).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(error.to_string().contains("non-directory"));
}

#[test]
fn test_open_dir_following_reports_missing_path_as_not_found() {
    let temp_dir = TempDir::new().unwrap();

    let error = open_dir_following(&temp_dir.path().join("missing"), DirectoryScope::LocalState)
        .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
}

#[cfg(unix)]
#[test]
fn test_open_dir_following_allows_final_directory_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let real = temp_dir.path().join("real");
    let alias = temp_dir.path().join("alias");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("entry"), "payload").unwrap();
    symlink(&real, &alias).unwrap();

    let opened = open_dir_following(&alias, DirectoryScope::LocalState).unwrap();

    assert_eq!(list_child_names_at(&opened).unwrap(), vec!["entry"]);
}

/// The link the operator named is what messages and repair hints have to show,
/// so the opened directory keeps the logical path rather than its target.
#[cfg(unix)]
#[test]
fn test_open_child_dir_following_opens_through_a_symlink_under_its_logical_path() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let real = temp_dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("entry"), "payload").unwrap();
    symlink(&real, temp_dir.path().join("alias")).unwrap();
    let parent = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let opened = open_child_dir_following(&parent, OsStr::new("alias")).unwrap();

    assert_eq!(list_child_names_at(&opened).unwrap(), vec!["entry"]);
    assert_eq!(opened.path(), temp_dir.path().join("alias"));
}

/// A path component is a byte string on Unix, and a directory whose name does
/// not decode as UTF-8 is an ordinary directory the operator may keep a root in.
/// The names kapsaro chooses itself keep their own rule, which the child-name
/// API below still enforces.
#[cfg(unix)]
#[test]
fn test_open_child_dir_following_opens_a_non_utf8_name() {
    let temp_dir = TempDir::new().unwrap();
    let name = non_utf8_name();
    let child = temp_dir.path().join(name);
    if !non_utf8_dir_can_be_created(
        &child,
        "test_open_child_dir_following_opens_a_non_utf8_name",
    ) {
        return;
    }
    fs::write(child.join("entry"), "payload").unwrap();
    let parent = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let opened = open_child_dir_following(&parent, name).unwrap();

    assert_eq!(list_child_names_at(&opened).unwrap(), vec!["entry"]);
    assert_eq!(opened.path(), child);
}

/// A root the operator chose is opened by the bytes its path holds, so a final
/// component that does not decode still reaches the directory it names.
#[cfg(unix)]
#[test]
fn test_anchored_root_opens_a_non_utf8_final_component() {
    let temp_dir = TempDir::new().unwrap();
    let root = temp_dir.path().join(non_utf8_name());
    if !non_utf8_dir_can_be_created(&root, "test_anchored_root_opens_a_non_utf8_final_component") {
        return;
    }

    let opened =
        AnchoredDir::open(&root, DirectoryScope::LocalState, "test local state root").unwrap();

    assert_eq!(opened.path(), root);
}

/// A directory name the kernel accepts as bytes and no decoder accepts as text.
#[cfg(unix)]
fn non_utf8_name() -> &'static OsStr {
    use std::os::unix::ffi::OsStrExt;

    OsStr::from_bytes(b"state\xFFdir")
}

/// Whether this filesystem lets a test create the entry it has to open.
///
/// A path component is a byte string as far as the kernel is concerned, but a
/// filesystem may enforce UTF-8 of its own: Apple's does, and refuses the name
/// with `EILSEQ`. Where the entry cannot be created there is nothing to open, so
/// the test says so and stops rather than asserting against a directory its own
/// setup never made. The decision these tests cover is pinned without a
/// filesystem by the anchor tests, which check the name is handed back as bytes.
#[cfg(unix)]
fn non_utf8_dir_can_be_created(path: &Path, test_name: &str) -> bool {
    match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) => {
            eprintln!(
                "skipping {test_name}: this filesystem refuses an entry whose name is not UTF-8 \
                 ({error}), so the directory the test has to open cannot be created here"
            );
            false
        }
    }
}

/// A link whose target is gone is a broken configuration rather than an absent
/// directory, so it is named as such instead of being reported as missing.
#[cfg(unix)]
#[test]
fn test_open_child_dir_following_reports_a_dangling_symlink_as_unsafe() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    symlink(temp_dir.path().join("gone"), temp_dir.path().join("alias")).unwrap();
    let parent = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let error = open_child_dir_following(&parent, OsStr::new("alias")).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(
        error
            .to_string()
            .contains("refusing to open a symlink whose target is missing"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn test_open_optional_child_dir_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, temp_dir.path().join("child")).unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        open_optional_child_dir(dir, "child").map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        error
            .to_string()
            .contains("refusing to open symlink as directory"),
        "{error}"
    );
}

#[test]
fn test_open_optional_child_dir_rejects_non_directory() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("child"), "payload").unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        open_optional_child_dir(dir, "child").map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(error.to_string().contains("non-directory"));
}

#[test]
fn test_open_optional_child_dir_returns_none_for_missing_entry() {
    let temp_dir = TempDir::new().unwrap();

    let child = with_locked_workspace_dir(temp_dir.path(), |dir| {
        open_optional_child_dir(dir, "missing")
    })
    .unwrap();

    assert!(child.is_none());
}

#[cfg(unix)]
#[test]
fn test_create_child_dir_restricted_at_uses_0700() {
    let temp_dir = TempDir::new().unwrap();
    with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap();

    let mode = fs::metadata(temp_dir.path().join("child"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn test_create_child_dir_restricted_at_refuses_an_existing_entry() {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join("child")).unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
}

/// Every failure before the publishing rename leaves the directory unstaged and
/// the name the caller asked for untouched.
///
/// The name only ever carries a finished directory, so a failure on the way
/// there has nothing to take back but the staged entry, and the name space is
/// left exactly as the call found it.
#[cfg(unix)]
#[test]
fn test_a_failure_before_the_publish_leaves_the_directory_unstaged() {
    let cases = [
        (
            ChildDirectoryCreationStep::Permission,
            "I/O error: Injected child directory permission failure",
        ),
        (
            ChildDirectoryCreationStep::ChildSync,
            "I/O error: Injected child directory sync failure",
        ),
        (
            ChildDirectoryCreationStep::Publish,
            "I/O error: Injected child directory publish failure",
        ),
    ];

    for (failure, expected_message) in cases {
        let temp_dir = TempDir::new().unwrap();

        fail_next_child_dir_creation_at(failure);

        let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
            create_child_dir_restricted_at(dir, "child").map(|_| ())
        })
        .unwrap_err();

        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(error.to_string(), expected_message);
        assert!(
            remaining_entry_names(temp_dir.path()).is_empty(),
            "{failure:?} left {:?} behind",
            remaining_entry_names(temp_dir.path())
        );
    }
}

/// The rename is the point the directory becomes reachable under its name, so a
/// failure after it leaves the directory standing and reports it as made.
///
/// Rolling it back would be the removal that takes a directory another caller
/// has already opened, and the directory is complete: its mode was settled
/// before the rename published it.
#[cfg(unix)]
#[test]
fn test_a_failure_after_the_publish_keeps_the_published_directory() {
    let temp_dir = TempDir::new().unwrap();

    fail_next_child_dir_creation_at(ChildDirectoryCreationStep::ParentSync);
    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap_err();

    let message = error.format_user_message();
    assert!(message.contains("was written, but"), "{message}");
    assert!(message.contains("not persisted"), "{message}");
    let child = temp_dir.path().join("child");
    assert!(child.is_dir(), "the rename already published the directory");
    assert_eq!(
        fs::metadata(&child).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

/// A directory somebody else put under the name is never removed by a creation
/// that gives up.
///
/// Both ways of giving up are checked: a failure on the way to the publish, and
/// a publish that finds the name taken. Neither call ever holds the entry under
/// that name, so the only thing either has to give up is its own staged
/// directory, and the entry that was there keeps its contents.
#[cfg(unix)]
#[test]
fn test_a_failed_creation_leaves_the_directory_a_concurrent_caller_holds() {
    let temp_dir = TempDir::new().unwrap();
    let child_path = temp_dir.path().join("child");
    fs::create_dir(&child_path).unwrap();
    fs::write(child_path.join("held"), "payload").unwrap();

    fail_next_child_dir_creation_at(ChildDirectoryCreationStep::ChildSync);
    let staging_failed = with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap_err();
    assert!(
        staging_failed.to_string().contains("Injected"),
        "{staging_failed}"
    );
    assert!(
        child_path.join("held").exists(),
        "a failure before the publish must leave the entry that was there alone"
    );

    let name_taken = with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap_err();
    assert_eq!(name_taken.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        child_path.join("held").exists(),
        "a publish that found the name taken must leave that entry alone"
    );
    assert_eq!(
        remaining_entry_names(temp_dir.path()),
        vec!["child".to_string()],
        "neither call may leave a staged directory behind"
    );
}

/// The entry the caller asked for is never seen half made, so a name that is
/// free stays free until a complete directory is renamed onto it.
#[cfg(unix)]
#[test]
fn test_the_name_a_creation_publishes_never_holds_an_unfinished_directory() {
    let temp_dir = TempDir::new().unwrap();

    fail_next_child_dir_creation_at(ChildDirectoryCreationStep::Publish);
    with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap_err();

    assert!(
        fs::symlink_metadata(temp_dir.path().join("child")).is_err(),
        "the final name must never have been created"
    );
}

/// The names left in a directory, so a staged entry that outlived its call is
/// named rather than only counted.
#[cfg(unix)]
fn remaining_entry_names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[cfg(unix)]
#[test]
fn test_ensure_child_dir_restricted_at_creates_owner_only_directory() {
    let temp_dir = TempDir::new().unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        ensure_child_dir_restricted_at(dir, "created").map(|_| ())
    })
    .unwrap();

    let created_mode = fs::metadata(temp_dir.path().join("created"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(created_mode, 0o700);
}

/// An existing child that group or other can reach is reused and named in a
/// warning, and its mode is left for the operator to repair. The warning
/// belongs to local state, so the check runs under a local state root.
#[cfg(unix)]
#[test]
fn test_ensure_child_dir_restricted_at_warns_about_insecure_existing_directory() {
    let temp_dir = crate::test_utils::local_state_temp_dir();
    let existing = temp_dir.path().join("existing");
    fs::create_dir(&existing).unwrap();
    fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
    let anchored = AnchoredDir::open(
        temp_dir.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();

    let guard = LocalStateWarningGuard::new();
    with_exclusive_locked_directory(&anchored, |dir| {
        ensure_child_dir_restricted_at(dir, "existing").map(|_| ())
    })
    .unwrap();
    let warnings = guard.take_reasons();

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0755"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("chmod 0700"), "{warnings:?}");
    assert_eq!(
        fs::metadata(&existing).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn test_ensure_child_dir_restricted_at_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, temp_dir.path().join("child")).unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        ensure_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        error
            .to_string()
            .contains("refusing to open symlink as directory"),
        "{error}"
    );
}

isolated_umask_test! {
    /// The mode `mkdirat` is given is filtered by the umask, so a umask that
    /// drops the owner bits would otherwise leave a directory nobody, its own
    /// owner included, can open.
    #[cfg(unix)]
    fn test_ensure_child_dir_restricted_pins_0700_under_a_restrictive_umask() {
        let temp_dir = TempDir::new().unwrap();

        with_restrictive_umask(|| {
            with_locked_workspace_dir(temp_dir.path(), |dir| {
                ensure_child_dir_restricted_at(dir, "child").map(|_| ())
            })
            .unwrap();
        });

        let child = temp_dir.path().join("child");
        let mode = fs::metadata(&child).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        fs::read_dir(&child).unwrap();
    }
}

isolated_umask_test! {
    /// The creating path settles the mode the same way, so a key directory
    /// staged under a restrictive umask is one the command can go on to write.
    #[cfg(unix)]
    fn test_create_child_dir_restricted_pins_0700_under_a_restrictive_umask() {
        let temp_dir = TempDir::new().unwrap();

        with_restrictive_umask(|| {
            with_locked_workspace_dir(temp_dir.path(), |dir| {
                create_child_dir_restricted_at(dir, "child").map(|_| ())
            })
            .unwrap();
        });

        let child = temp_dir.path().join("child");
        let mode = fs::metadata(&child).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        fs::read_dir(&child).unwrap();
    }
}

/// A directory that could not be completed leaves the caller with nothing to
/// use, so the entry it staged is removed rather than left standing.
#[cfg(unix)]
#[test]
fn test_ensure_child_dir_removes_what_a_failed_creation_staged() {
    let temp_dir = TempDir::new().unwrap();

    fail_next_child_dir_creation_at(ChildDirectoryCreationStep::Permission);
    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        ensure_child_dir_restricted_at(dir, "child").map(|_| ())
    })
    .unwrap_err();

    assert!(error.to_string().contains("Injected"), "{error}");
    assert!(remaining_entry_names(temp_dir.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn test_list_child_entries_at_classifies_without_following_symlinks() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join("directory")).unwrap();
    fs::write(temp_dir.path().join("file"), "payload").unwrap();
    symlink("file", temp_dir.path().join("link")).unwrap();
    create_fifo(&temp_dir.path().join("pipe"));

    let entries =
        with_locked_workspace_dir(temp_dir.path(), |dir| list_child_entries_at(dir)).unwrap();

    assert_eq!(
        entries,
        vec![
            ("directory".to_string(), ChildType::Directory),
            ("file".to_string(), ChildType::RegularFile),
            ("link".to_string(), ChildType::Symlink),
            ("pipe".to_string(), ChildType::Other),
        ]
    );
}

#[cfg(unix)]
#[test]
fn test_regular_file_exists_at_accepts_only_regular_files() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("file"), "payload").unwrap();
    symlink("file", temp_dir.path().join("link")).unwrap();
    fs::create_dir(temp_dir.path().join("directory")).unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        assert!(regular_file_exists_at(dir, "file")?);
        assert!(!regular_file_exists_at(dir, "missing")?);
        for name in ["link", "directory"] {
            let error = regular_file_exists_at(dir, name).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_rename_child_noreplace_preserves_existing_destination() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("source"), "source").unwrap();
    fs::write(temp_dir.path().join("destination"), "destination").unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        rename_child_noreplace_unsynced_at(dir, "source", "destination")
    })
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(
        fs::read_to_string(temp_dir.path().join("source")).unwrap(),
        "source"
    );
    assert_eq!(
        fs::read_to_string(temp_dir.path().join("destination")).unwrap(),
        "destination"
    );
}

#[test]
fn test_create_text_noreplace_publishes_a_new_entry() {
    let temp_dir = TempDir::new().unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_text_noreplace_at(dir, "alice.json", "{}")
    })
    .unwrap();

    assert_eq!(
        fs::read_to_string(temp_dir.path().join("alice.json")).unwrap(),
        "{}"
    );
}

#[test]
fn test_create_text_noreplace_preserves_an_entry_that_already_stands() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("alice.json"), "existing").unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_text_noreplace_at(dir, "alice.json", "{}")
    })
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(
        fs::read_to_string(temp_dir.path().join("alice.json")).unwrap(),
        "existing"
    );
}

/// The staging name is formed inside the write, so a target that fits an atomic
/// write is publishable. A caller that staged under a name of its own and then
/// saved that name paid the suffix twice and lost the top of the allowed range.
#[test]
fn test_create_text_noreplace_accepts_the_longest_writable_target_name() {
    let temp_dir = TempDir::new().unwrap();
    let name = "a".repeat(MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH);

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_text_noreplace_at(dir, &name, "{}")
    })
    .unwrap();

    assert_eq!(
        fs::read_to_string(temp_dir.path().join(&name)).unwrap(),
        "{}"
    );
}

#[test]
fn test_create_text_noreplace_rejects_a_target_name_past_the_atomic_write_bound() {
    let temp_dir = TempDir::new().unwrap();
    let name = "a".repeat(MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH + 1);

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_text_noreplace_at(dir, &name, "{}")
    })
    .unwrap_err();

    assert!(
        error.to_string().contains("file name too long"),
        "unexpected error: {error}"
    );
}

/// A failed publish leaves the directory as it found it, so the next caller
/// does not have to tell a staged entry from a document.
#[test]
fn test_create_text_noreplace_leaves_no_staged_entry_behind() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("alice.json"), "existing").unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        create_text_noreplace_at(dir, "alice.json", "{}").unwrap_err();
        Ok(())
    })
    .unwrap();

    let mut entries: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(entries, vec![std::ffi::OsString::from("alice.json")]);
}

#[test]
fn test_rename_child_noreplace_moves_entry() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("source"), "payload").unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        rename_child_noreplace_unsynced_at(dir, "source", "destination")
    })
    .unwrap();

    assert!(!temp_dir.path().join("source").exists());
    assert_eq!(
        fs::read_to_string(temp_dir.path().join("destination")).unwrap(),
        "payload"
    );
}

#[cfg(unix)]
#[test]
fn test_remove_file_if_exists_at_unlinks_symlink_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside");
    fs::write(&outside, "payload").unwrap();
    symlink(&outside, temp_dir.path().join("link")).unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        remove_file_if_exists_at(dir, "link")?;
        remove_file_if_exists_at(dir, "link")
    })
    .unwrap();

    assert_eq!(fs::read_to_string(outside).unwrap(), "payload");
    assert!(!temp_dir.path().join("link").exists());
}

#[test]
fn test_remove_empty_child_dir_if_exists_at_is_relative_and_idempotent() {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join("child")).unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        remove_empty_child_dir_if_exists_at(dir, "child")?;
        remove_empty_child_dir_if_exists_at(dir, "child")
    })
    .unwrap();

    assert!(!temp_dir.path().join("child").exists());
}

#[cfg(unix)]
#[test]
fn test_opened_child_stays_bound_after_path_swap() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let child_path = temp_dir.path().join("child");
    let moved_path = temp_dir.path().join("child.real");
    let outside = temp_dir.path().join("outside");
    fs::create_dir(&child_path).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(child_path.join("remove-me"), "inside").unwrap();
    fs::write(outside.join("remove-me"), "outside").unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        let child = open_child_dir(dir, "child")?;
        fs::rename(&child_path, &moved_path).unwrap();
        symlink(&outside, &child_path).unwrap();
        save_text_at(&child, "created", "inside")?;
        remove_file_if_exists_at(&child, "remove-me")
    })
    .unwrap();

    assert_eq!(
        fs::read_to_string(moved_path.join("created")).unwrap(),
        "inside"
    );
    assert!(!moved_path.join("remove-me").exists());
    assert!(!outside.join("created").exists());
    assert_eq!(
        fs::read_to_string(outside.join("remove-me")).unwrap(),
        "outside"
    );
}

#[test]
fn test_relative_read_and_write_roundtrip() {
    let temp_dir = TempDir::new().unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        save_text_at(dir, "data.txt", "hello")?;
        let content = load_text_with_limit_at(dir, "data.txt", 16, "test file")?;

        assert_eq!(content, "hello");
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_relative_list_child_names_returns_sorted_entries() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("b.txt"), "b").unwrap();
    fs::write(temp_dir.path().join("a.txt"), "a").unwrap();

    let names = with_locked_workspace_dir(temp_dir.path(), |dir| list_child_names_at(dir)).unwrap();

    assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
}

/// A name kapsaro cannot decode came from somewhere else, so it is reported
/// rather than dropped. Skipping it would hide the entry from every caller.
///
/// Apple filesystems refuse to create such a name at all, so there is nothing
/// to set up there.
#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn test_relative_list_child_names_reports_a_non_utf8_entry() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("a.txt"), "a").unwrap();
    fs::write(temp_dir.path().join(OsString::from_vec(vec![0xff])), "x").unwrap();

    let error =
        with_locked_workspace_dir(temp_dir.path(), |dir| list_child_names_at(dir)).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        error.format_user_message().contains("name is not UTF-8"),
        "{}",
        error.format_user_message()
    );
}

#[test]
fn test_relative_helpers_reject_nested_name() {
    let temp_dir = TempDir::new().unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        save_text_at(dir, "../escaped.txt", "payload")
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("single path component"),
        "unexpected error: {message}"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_read_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside.txt");
    fs::write(&outside, "secret").unwrap();
    symlink(&outside, temp_dir.path().join("link.txt")).unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        load_text_with_limit_at(dir, "link.txt", 16, "test file").map(|_| ())
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("refusing to read non-regular file"),
        "unexpected error: {message}"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_read_rejects_fifo_without_blocking() {
    let temp_dir = TempDir::new().unwrap();
    let fifo_path = temp_dir.path().join("pipe");
    create_fifo(&fifo_path);

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        load_text_with_limit_at(dir, "pipe", 16, "test file").map(|_| ())
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains("refusing to read non-regular file"),
        "unexpected error: {message}"
    );
}

#[cfg(unix)]
fn create_fifo(path: &std::path::Path) {
    use std::ffi::CString;

    let c_path = CString::new(path.to_str().unwrap()).unwrap();
    // mkfifo has no safe wrapper. The path is a valid CString inside a
    // temporary directory this test owns.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
}

#[cfg(unix)]
#[test]
/// The staged file is renamed onto the name inside the opened directory, and
/// rename replaces the link itself. A symlinked target therefore becomes a
/// regular file holding the new content, and what it pointed at keeps its own.
fn test_relative_save_replaces_symlink_target_in_place() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let outside = temp_dir.path().join("outside.txt");
    let link_path = temp_dir.path().join("link.txt");
    fs::write(&outside, "original").unwrap();
    symlink(&outside, &link_path).unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        save_text_at(dir, "link.txt", "changed")
    })
    .unwrap();

    assert_eq!(fs::read_to_string(&outside).unwrap(), "original");
    assert_eq!(fs::read_to_string(&link_path).unwrap(), "changed");
    assert!(fs::symlink_metadata(&link_path)
        .unwrap()
        .file_type()
        .is_file());
}

#[cfg(unix)]
#[test]
fn test_relative_save_stays_on_opened_directory_after_path_swap() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let locked_path = temp_dir.path().join("locked");
    let renamed_path = temp_dir.path().join("locked.real");
    let outside_dir = temp_dir.path().join("outside");
    fs::create_dir(&locked_path).unwrap();
    fs::create_dir(&outside_dir).unwrap();

    with_locked_workspace_dir(&locked_path, |dir| {
        fs::rename(&locked_path, &renamed_path).unwrap();
        symlink(&outside_dir, &locked_path).unwrap();
        save_text_at(dir, "data.txt", "payload")
    })
    .unwrap();

    assert_eq!(
        fs::read_to_string(renamed_path.join("data.txt")).unwrap(),
        "payload"
    );
    assert!(
        !outside_dir.join("data.txt").exists(),
        "fd-relative write must not follow the replaced path"
    );
}

#[cfg(unix)]
#[test]
fn test_relative_permission_check_uses_the_file_that_was_read() {
    use std::os::unix::fs::symlink;

    let temp_dir = crate::test_utils::local_state_temp_dir();
    let opened_path = temp_dir.path().join("opened");
    let original_path = temp_dir.path().join("opened.original");
    let outside_path = temp_dir.path().join("outside");
    fs::create_dir(&opened_path).unwrap();
    fs::create_dir(&outside_path).unwrap();
    fs::write(opened_path.join("data"), "original").unwrap();
    fs::set_permissions(opened_path.join("data"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(outside_path.join("data"), "outside").unwrap();
    fs::set_permissions(outside_path.join("data"), fs::Permissions::from_mode(0o666)).unwrap();

    let anchored =
        AnchoredDir::open(&opened_path, DirectoryScope::LocalState, "test directory").unwrap();
    let guard = LocalStateWarningGuard::new();
    let content = with_exclusive_locked_directory(&anchored, |dir| {
        fs::rename(&opened_path, &original_path).unwrap();
        symlink(&outside_path, &opened_path).unwrap();
        load_text_with_limit_at(dir, "data", 32, "test file")
    })
    .unwrap();
    let warnings = guard.take_reasons();

    assert_eq!(content, "original");
    assert!(warnings.is_empty(), "{warnings:?}");
}

/// Following the link happens once, when the root is opened. Repointing it
/// afterwards leaves the descriptor on the directory it resolved to, so the
/// writes keep landing there.
#[cfg(unix)]
#[test]
fn test_anchored_dir_opened_through_a_symlink_stays_bound_after_the_link_moves() {
    use std::os::unix::fs::symlink;

    let temp_dir = crate::test_utils::local_state_temp_dir();
    let original = temp_dir.path().join("original");
    let outside = temp_dir.path().join("outside");
    let alias = temp_dir.path().join("alias");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&original, &alias).unwrap();
    let anchored =
        AnchoredDir::open(&alias, DirectoryScope::LocalState, "test local state root").unwrap();

    fs::remove_file(&alias).unwrap();
    symlink(&outside, &alias).unwrap();
    save_text_at(&anchored, "data.txt", "payload").unwrap();

    assert_eq!(
        fs::read_to_string(original.join("data.txt")).unwrap(),
        "payload"
    );
    assert!(!outside.join("data.txt").exists());
}

/// The operator repairs the path they selected, and `chmod` follows the link,
/// so the warning names the link rather than the directory behind it.
#[cfg(unix)]
#[test]
fn test_anchored_dir_permission_warning_names_the_selected_symlink_path() {
    use std::os::unix::fs::symlink;

    let temp_dir = crate::test_utils::local_state_temp_dir();
    let real = temp_dir.path().join("real");
    let alias = temp_dir.path().join("alias");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&real, &alias).unwrap();

    let guard = LocalStateWarningGuard::new();
    AnchoredDir::create(&alias, DirectoryScope::LocalState, "test local state root").unwrap();
    let warnings = guard.take_reasons();

    let alias_display = alias.display().to_string();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("Insecure permissions 0755")
                && warning.contains(&alias_display)),
        "{warnings:?}"
    );
}

isolated_umask_test! {
    #[cfg(unix)]
    fn test_relative_restricted_save_preserves_0600_with_restrictive_umask() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("secret.txt");

        with_restrictive_umask(|| {
            with_locked_workspace_dir(temp_dir.path(), |dir| {
                save_text_restricted_at(dir, "secret.txt", "payload")
            })
            .unwrap();
        });

        let mode = fs::metadata(target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn test_relative_remove_deletes_only_locked_directory_entry() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("data.txt"), "payload").unwrap();

    with_locked_workspace_dir(temp_dir.path(), |dir| {
        assert!(file_exists_at(dir, "data.txt")?);
        assert!(matches!(
            remove_file_at(dir, "data.txt")?,
            RemovedEntry::Persisted
        ));
        assert!(!file_exists_at(dir, "data.txt")?);
        Ok(())
    })
    .unwrap();
}

/// The unlink is the point the name stops resolving, so a sync that fails after
/// it is about durability rather than about a removal that never happened.
///
/// A caller told only that the removal failed would report a document as still
/// there when the name it stood under is already free.
#[cfg(unix)]
#[test]
fn test_remove_reports_an_unlinked_entry_whose_directory_was_not_persisted() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("data.txt"), "payload").unwrap();

    fail_next_parent_sync();
    let removed =
        with_locked_workspace_dir(temp_dir.path(), |dir| remove_file_at(dir, "data.txt")).unwrap();

    assert!(
        matches!(removed, RemovedEntry::Unpersisted(_)),
        "{removed:?}"
    );
    assert!(
        !temp_dir.path().join("data.txt").exists(),
        "the unlink already took the entry"
    );
}

/// A write addressed by path has to land where the caller named it, so an entry
/// standing in the final position that is not a directory of its own is refused
/// rather than followed or opened as one.
#[cfg(unix)]
#[test]
fn test_open_dir_nofollow_refuses_a_final_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let real = temp_dir.path().join("real");
    let alias = temp_dir.path().join("alias");
    fs::create_dir(&real).unwrap();
    symlink(&real, &alias).unwrap();

    let error = open_dir_nofollow(&alias, DirectoryScope::Generic).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        error
            .to_string()
            .contains("refusing to open symlink as directory"),
        "{error}"
    );
}

#[test]
fn test_open_dir_nofollow_refuses_a_regular_file() {
    let temp_dir = TempDir::new().unwrap();
    let file = temp_dir.path().join("not_a_directory");
    fs::write(&file, b"payload").unwrap();

    let error = open_dir_nofollow(&file, DirectoryScope::Generic).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(error.to_string().contains("non-directory"), "{error}");
}

#[test]
fn test_open_dir_nofollow_reports_a_missing_path_as_not_found() {
    let temp_dir = TempDir::new().unwrap();

    let error =
        open_dir_nofollow(&temp_dir.path().join("missing"), DirectoryScope::Generic).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
}

/// A target that fits `NAME_MAX` can still be unwritable, because the atomic
/// write stages it under a longer temporary name. The bound is reported against
/// the target the caller chose.
#[test]
fn test_save_text_at_rejects_a_target_name_the_staging_name_cannot_hold() {
    let dir = TempDir::new().unwrap();
    let anchored =
        AnchoredDir::open(dir.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let name = "a".repeat(MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH + 1);

    let error = save_text_at(&anchored, &name, "content")
        .expect_err("a target name the staging name cannot hold must be rejected");

    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
    let message = error.format_user_message();
    assert!(
        message.contains("too long for an atomic write"),
        "{message}"
    );
}

#[test]
fn test_save_text_at_accepts_the_longest_writable_target_name() {
    let dir = TempDir::new().unwrap();
    let anchored =
        AnchoredDir::open(dir.path(), DirectoryScope::LocalState, "test directory").unwrap();
    let name = "a".repeat(MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH);

    save_text_at(&anchored, &name, "content").unwrap();

    assert_eq!(
        std::fs::read_to_string(dir.path().join(&name)).unwrap(),
        "content"
    );
}

/// Both staging shapes carry a hyphenated UUID, which is what separates them
/// from ordinary hidden names an operator or another tool may have left.
#[test]
fn test_write_staging_names_are_recognised_by_shape() {
    let uuid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    assert!(is_write_staging_name(&format!(".config.toml.tmp.{uuid}")));
    assert!(is_write_staging_name(&format!(".tmp-{uuid}")));
    assert!(!is_write_staging_name(".config.toml.tmp.stale"));
    assert!(!is_write_staging_name(".tmp-backup"));
    assert!(!is_write_staging_name(".DS_Store"));
    assert!(!is_write_staging_name(&format!("config.toml.tmp.{uuid}")));
}

/// A read that fails to decode must not carry the file into the error.
///
/// `String::from_utf8` hands the whole buffer back inside `FromUtf8Error`, and
/// an error holding that as its source prints the file when it is formatted
/// with `{:?}`. Private keys are read through this path.
#[cfg(unix)]
#[test]
fn test_load_text_at_keeps_the_file_contents_out_of_the_error() {
    let temp_dir = TempDir::new().unwrap();
    let secret = b"BEGIN-PRIVATE-KEY-\xffsecret-material";
    fs::write(temp_dir.path().join("private.json"), secret).unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        load_text_with_limit_at(dir, "private.json", 128, "test file").map(|_| ())
    })
    .unwrap_err();

    let debug = format!("{error:?}");
    assert!(
        !debug.contains("secret-material"),
        "the file contents must not reach the error: {debug}"
    );
    assert!(
        !debug.contains("BEGIN-PRIVATE-KEY"),
        "the file contents must not reach the error: {debug}"
    );
    assert_eq!(error.kind(), crate::ErrorKind::Parse);
}

/// A second inspection that fails for its own reason is that failure, not an
/// absence. Collapsing it into "nothing is there" would report a directory
/// kapsaro is not allowed to look at as one that does not exist.
#[cfg(unix)]
#[test]
fn test_missing_child_dir_separates_an_absence_from_a_denied_inspection() {
    let path = Path::new("/local/state/keys");

    let absent = classify_missing_child_dir(
        Err(rustix::io::Errno::NOENT),
        DirectoryScope::LocalState,
        path,
    );
    assert_eq!(absent.kind(), crate::ErrorKind::NotFound);

    let denied = classify_missing_child_dir(
        Err(rustix::io::Errno::ACCESS),
        DirectoryScope::LocalState,
        path,
    );
    assert_eq!(denied.kind(), crate::ErrorKind::Io);
    assert!(
        denied.format_user_message().contains("Failed to inspect"),
        "{}",
        denied.format_user_message()
    );

    let dangling = classify_missing_child_dir(Ok(()), DirectoryScope::LocalState, path);
    assert_eq!(dangling.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        dangling
            .format_user_message()
            .contains("refusing to open a symlink whose target is missing"),
        "{}",
        dangling.format_user_message()
    );
}

/// The rename is the point the content becomes readable, so a sync that fails
/// afterwards is about durability. Reporting it as a failed write would send the
/// operator to save again over content that is already on disk.
#[cfg(unix)]
#[test]
fn test_save_reports_a_published_file_whose_entry_was_not_persisted() {
    let temp_dir = TempDir::new().unwrap();

    fail_next_parent_sync();
    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        save_text_at(dir, "data.txt", "payload")
    })
    .unwrap_err();

    let message = error.format_user_message();
    assert!(message.contains("was written, but"), "{message}");
    assert!(message.contains("not persisted"), "{message}");
    assert_eq!(
        fs::read_to_string(temp_dir.path().join("data.txt")).unwrap(),
        "payload",
        "the rename already published the file"
    );
}

isolated_umask_test! {
    /// An ordinary write keeps the mode the umask allows, and adds the owner
    /// bits back. Without that a restrictive umask leaves behind a file its own
    /// owner cannot read.
    #[cfg(unix)]
    fn test_relative_save_stays_readable_by_its_owner_under_a_restrictive_umask() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("shared.txt");

        with_restrictive_umask(|| {
            with_locked_workspace_dir(temp_dir.path(), |dir| {
                save_text_at(dir, "shared.txt", "payload")
            })
            .unwrap();
        });

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "payload");
    }
}

isolated_umask_test! {
    /// A workspace file is shared through git, so an ordinary umask leaves the
    /// group and other read bits the checkout expects.
    #[cfg(unix)]
    fn test_relative_save_follows_an_ordinary_umask() {
        use crate::support::fs::test_umask::with_umask;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("members.json");

        with_umask(0o022, || {
            with_locked_workspace_dir(temp_dir.path(), |dir| {
                save_text_at(dir, "members.json", "payload")
            })
            .unwrap();
        });

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }
}

isolated_umask_test! {
    /// A workspace directory keeps the umask-derived mode instead of the
    /// owner-only one local state carries.
    #[cfg(unix)]
    fn test_ensure_child_dir_at_follows_the_umask() {
        use crate::support::fs::test_umask::with_umask;

        let temp_dir = TempDir::new().unwrap();

        with_umask(0o022, || {
            with_locked_workspace_dir(temp_dir.path(), |dir| {
                ensure_child_dir_at(dir, "secrets").map(|_| ())
            })
            .unwrap();
        });

        let mode = fs::metadata(temp_dir.path().join("secrets"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }
}

isolated_umask_test! {
    /// The scope decides the mode: local state is owner-only whatever the umask
    /// allows, and a workspace directory keeps what the umask produced.
    #[cfg(unix)]
    fn test_ensure_scoped_child_dir_at_follows_the_scope_of_its_parent() {
        use super::{ensure_scoped_child_dir_at, open_dir_following};
        use crate::support::fs::test_umask::with_umask;

        let temp_dir = crate::test_utils::local_state_temp_dir();
        let local = temp_dir.path().join("local");
        let shared = temp_dir.path().join("shared");
        fs::create_dir(&local).unwrap();
        fs::create_dir(&shared).unwrap();

        with_umask(0o022, || {
            let local_root = open_dir_following(&local, DirectoryScope::LocalState).unwrap();
            ensure_scoped_child_dir_at(&local_root, "keys").unwrap();
            let shared_root = open_dir_following(&shared, DirectoryScope::Generic).unwrap();
            ensure_scoped_child_dir_at(&shared_root, "secrets").unwrap();
        });

        assert_eq!(dir_mode(&local.join("keys")), 0o700);
        assert_eq!(dir_mode(&shared.join("secrets")), 0o755);
    }
}

#[cfg(unix)]
fn dir_mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The decoded names a directory holds, in the order the walk returned them.
fn list_child_names_at<D>(dir: &D) -> crate::Result<Vec<String>>
where
    D: DirectoryFd,
{
    Ok(list_child_entries_at(dir)?
        .into_iter()
        .map(|(name, _)| name)
        .collect())
}

/// A budgeted scan stops reading the directory, rather than inspecting all of
/// it and handing back the part the caller asked for.
///
/// A caller that bounds how much it judges gains nothing if the listing behind
/// it still costs one `statat` per entry, so the number kept is what the bound
/// says and no more.
#[test]
fn test_scan_child_entries_at_stops_at_the_budget() {
    let temp_dir = TempDir::new().unwrap();
    for index in 0..12 {
        fs::write(temp_dir.path().join(format!("entry{index}")), b"x").unwrap();
    }
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::Generic).unwrap();

    let scanned = scan_child_entries_at(&dir, ScanBudget::AtMost(4)).unwrap();

    assert_eq!(
        scanned.entries.len(),
        4,
        "the scan must keep no more entries than the budget allows"
    );
    assert!(
        scanned.truncated,
        "the caller must learn the directory held more than it was given"
    );
}

/// The budget is charged for every entry the scan inspects, including one that
/// was already gone by the time it was looked at.
///
/// The `statat` for a vanished entry costs the same as any other, so a caller
/// that asked for a bounded scan is charged for it. Counting only the entries
/// handed back would let a directory whose entries keep disappearing draw an
/// unbounded number of them.
#[cfg(unix)]
#[test]
fn test_scan_child_entries_at_charges_the_budget_for_an_entry_that_vanished() {
    let temp_dir = TempDir::new().unwrap();
    for index in 0..3 {
        fs::write(temp_dir.path().join(format!("entry{index}")), b"x").unwrap();
    }
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::Generic).unwrap();

    vanish_next_scanned_child();
    let scanned = scan_child_entries_at(&dir, ScanBudget::AtMost(2)).unwrap();

    assert_eq!(
        scanned.entries.len(),
        1,
        "the entry that vanished spent budget the scan cannot hand back"
    );
    assert!(
        scanned.truncated,
        "the caller must learn the directory held more than the budget covered"
    );
}

/// A budget the directory fits inside returns everything and says so.
#[test]
fn test_scan_child_entries_at_reports_a_directory_that_fits_the_budget() {
    let temp_dir = TempDir::new().unwrap();
    for index in 0..3 {
        fs::write(temp_dir.path().join(format!("entry{index}")), b"x").unwrap();
    }
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::Generic).unwrap();

    let scanned = scan_child_entries_at(&dir, ScanBudget::AtMost(3)).unwrap();

    assert_eq!(scanned.entries.len(), 3);
    assert!(
        !scanned.truncated,
        "a directory that fits the budget was read whole"
    );
}

/// Content that still matches what the reviewer read is accepted.
#[test]
fn test_ensure_text_file_content_matches_at_accepts_unchanged_content() {
    let temp_dir = TempDir::new().unwrap();
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::Generic).unwrap();
    save_text_at(&dir, "doc", "reviewed").unwrap();

    ensure_text_file_content_matches_at(&dir, "doc", Some("reviewed"), "Document", 1024).unwrap();
}

/// A file the reviewer read that is gone now has changed since the review.
#[test]
fn test_ensure_text_file_content_matches_at_reports_a_removed_file_as_changed() {
    let temp_dir = TempDir::new().unwrap();
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::Generic).unwrap();

    let error =
        ensure_text_file_content_matches_at(&dir, "gone", Some("reviewed"), "Document", 1024)
            .expect_err("a file that is no longer there has changed");

    assert!(
        error.format_user_message().contains("changed since review"),
        "{}",
        error.format_user_message()
    );
}

/// A read that failed for its own reason leaves the question open, and saying
/// "changed since review" would send the operator to review a file when what
/// they have to fix is the read.
#[cfg(unix)]
#[test]
fn test_ensure_text_file_content_matches_at_separates_a_failed_read_from_a_change() {
    if !permission_denial_can_be_staged(
        "test_ensure_text_file_content_matches_at_separates_a_failed_read_from_a_change",
    ) {
        return;
    }
    let temp_dir = TempDir::new().unwrap();
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::Generic).unwrap();
    save_text_at(&dir, "doc", "reviewed").unwrap();
    fs::set_permissions(
        temp_dir.path().join("doc"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();

    let error =
        ensure_text_file_content_matches_at(&dir, "doc", Some("reviewed"), "Document", 1024)
            .expect_err("a read that was refused is not an answer about the content");

    let message = error.format_user_message();
    assert!(
        message.contains("could not be compared"),
        "the failure says the comparison never happened: {message}"
    );
}

/// Content past the size cap is the same case: the file was never compared.
#[test]
fn test_ensure_text_file_content_matches_at_separates_an_oversized_file_from_a_change() {
    let temp_dir = TempDir::new().unwrap();
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::Generic).unwrap();
    save_text_at(&dir, "doc", &"x".repeat(64)).unwrap();

    let error = ensure_text_file_content_matches_at(&dir, "doc", Some("reviewed"), "Document", 8)
        .expect_err("a file too large to read is not an answer about the content");

    assert!(
        error
            .format_user_message()
            .contains("could not be compared"),
        "{}",
        error.format_user_message()
    );
}

/// An entry another command removed between the listing and the inspection is
/// left out of the result. Reporting the gap as an unreadable entry would end
/// the whole listing over a directory that is perfectly fine.
#[cfg(unix)]
#[test]
fn test_scan_leaves_out_an_entry_that_is_no_longer_there() {
    let temp_dir = TempDir::new().unwrap();
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let scanned = scan_one_child(&dir, ChildName::from_raw_bytes(b"vanished"));

    assert!(scanned.is_none());
}

/// An entry name is chosen by whoever can write the directory, so a newline in
/// one is spelled out rather than left to forge a second reported line.
#[cfg(unix)]
#[test]
fn test_opening_a_scanned_child_escapes_the_name_it_reports() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("bad\nname"), "payload").unwrap();
    let dir = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let error = open_scanned_child_dir(&dir, &ChildName::from_raw_bytes(b"bad\nname"))
        .expect_err("a regular file is not a directory");

    let message = error.format_user_message();
    assert!(message.contains("bad\\nname"), "{message}");
    assert!(!message.contains('\n'), "{message}");
}

/// The directory a failed listing names carries an entry name of its own once
/// the walk has gone below the root, so it is escaped the same way.
#[cfg(unix)]
#[test]
fn test_a_directory_read_failure_escapes_the_directory_it_names() {
    let temp_dir = TempDir::new().unwrap();
    let directory = temp_dir.path().join("bad\nname");
    fs::create_dir(&directory).unwrap();
    let dir = open_dir_following(&directory, DirectoryScope::LocalState).unwrap();

    let error = read_directory_entry_error(&dir, rustix::io::Errno::IO);

    let message = error.format_user_message();
    assert!(message.contains("bad\\nname"), "{message}");
    assert!(!message.contains('\n'), "{message}");
}
