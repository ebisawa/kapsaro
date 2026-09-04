// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the anchored root-directory capability's create path.
//! Covers multi-level creation, the concurrent-creation race it absorbs, and
//! the pure helpers that classify a root path and translate its errors.

use super::{
    parent_and_name, required_parent_and_name, run_before_ancestor_search, with_subject,
    AnchoredDir, DirectoryFd, DirectoryScope,
};
#[cfg(unix)]
use crate::test_utils::permission_denial_can_be_staged;
use crate::{Error, ErrorKind};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn create_makes_every_missing_ancestor_below_an_existing_root() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("level1").join("level2").join("level3");

    let anchored = AnchoredDir::ensure(&target, DirectoryScope::Generic, "test root").unwrap();

    assert!(temp.path().join("level1").is_dir());
    assert!(temp.path().join("level1").join("level2").is_dir());
    assert!(target.is_dir());
    assert_eq!(anchored.path(), target.as_path());
}

/// A concurrent process can finish creating the whole tree between the probe
/// `create` makes and the one `ensure_final_directory` makes internally, and
/// the walk must absorb that by opening what is now there rather than trying
/// to create a directory that already exists.
#[test]
fn create_absorbs_a_full_tree_created_between_the_two_existence_checks() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("racing").join("root");
    let racing_target = target.clone();
    run_before_ancestor_search(move || {
        fs::create_dir_all(&racing_target).unwrap();
    });

    let anchored = AnchoredDir::ensure(&target, DirectoryScope::Generic, "test root").unwrap();

    assert_eq!(anchored.path(), target.as_path());
    assert!(target.is_dir());
}

/// A path this call cannot even stat, for a reason other than it being
/// missing, is reported as an inspection failure rather than folded into the
/// creation path meant for a path that is simply not there yet.
#[cfg(unix)]
#[test]
fn create_reports_an_inspection_failure_it_cannot_classify_as_missing() {
    if !permission_denial_can_be_staged(
        "create_reports_an_inspection_failure_it_cannot_classify_as_missing",
    ) {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().unwrap();
    let blocked = temp.path().join("blocked");
    fs::create_dir(&blocked).unwrap();
    let target = blocked.join("child");
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();

    let result = AnchoredDir::ensure(&target, DirectoryScope::Generic, "test root");
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
    let error = result.unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Io);
    assert!(error.to_string().contains("Failed to inspect test root"));
}

/// A root path names an entry whose name may have been chosen by somebody else,
/// and a newline in it would forge a second line on standard error, so the
/// failure spells the control character out instead of passing it through.
#[cfg(unix)]
#[test]
fn open_spells_out_a_control_character_in_the_root_it_could_not_find() {
    let temp = TempDir::new().unwrap();
    let missing = temp.path().join("gone\nWarning: forged");

    let error = AnchoredDir::open(&missing, DirectoryScope::Generic, "test root").unwrap_err();

    let message = error.format_user_message();
    assert!(!message.contains('\n'), "{message}");
    assert!(
        message.contains("gone\\nWarning: forged"),
        "unexpected error: {message}"
    );
}

#[test]
fn parent_and_name_splits_a_path_that_has_a_parent_component() {
    let result = parent_and_name(Path::new("/tmp/foo/bar"));

    assert_eq!(result, Some((Path::new("/tmp/foo"), OsStr::new("bar"))));
}

/// A bare relative name has an empty parent, which is not a usable directory
/// to open, so the walk falls back to the current directory instead.
#[test]
fn parent_and_name_falls_back_to_the_current_directory_for_a_bare_name() {
    let result = parent_and_name(Path::new("just-name"));

    assert_eq!(result, Some((Path::new("."), OsStr::new("just-name"))));
}

/// A path with no final component names nothing this helper could open, so it
/// reports that rather than a parent and a name.
#[test]
fn parent_and_name_reports_no_final_component_for_the_root_path() {
    let result = parent_and_name(Path::new("/"));

    assert_eq!(result, None);
}

/// A root is named by the operator and the OS, and a Unix path component is a
/// byte string, so a final component that does not decode is handed back as the
/// bytes it holds rather than refused.
#[cfg(unix)]
#[test]
fn parent_and_name_hands_back_a_non_utf8_final_component() {
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    let name = OsStr::from_bytes(b"\xffname");
    let path = PathBuf::from(OsStr::from_bytes(b"/tmp/parent/\xffname"));

    let result = parent_and_name(&path);

    assert_eq!(result, Some((Path::new("/tmp/parent"), name)));
}

/// A component kapsaro has to create is one it will address by name from then
/// on, so that name still has to decode. The scope decides how the refusal reads.
#[cfg(unix)]
#[test]
fn creating_a_non_utf8_component_is_refused_under_each_scope() {
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    let path = PathBuf::from(OsStr::from_bytes(b"/tmp/parent/\xffname"));

    let local_state =
        required_parent_and_name(&path, DirectoryScope::LocalState, "local state root")
            .unwrap_err();
    assert_eq!(local_state.kind(), ErrorKind::InvalidOperation);
    assert_eq!(local_state.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(local_state.to_string().contains("not UTF-8"));

    let generic =
        required_parent_and_name(&path, DirectoryScope::Generic, "workspace root").unwrap_err();
    assert_eq!(generic.kind(), ErrorKind::InvalidOperation);
    assert_eq!(generic.rule(), None);
    assert!(generic.to_string().contains("not UTF-8"));
}

#[test]
fn with_subject_names_the_subject_that_does_not_exist() {
    let inner = Error::build_not_found_error("boom");

    let error = with_subject(
        inner,
        DirectoryScope::Generic,
        "test root",
        Path::new("/tmp/root"),
    );

    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(
        error.format_user_message(),
        "test root does not exist: /tmp/root"
    );
}

#[test]
fn with_subject_marks_an_invalid_operation_as_local_state_unsafe() {
    let inner = Error::build_invalid_operation_error("non-directory");

    let error = with_subject(
        inner,
        DirectoryScope::LocalState,
        "local state root",
        Path::new("/tmp/root"),
    );

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(error
        .format_user_message()
        .contains("Failed to open local state root '/tmp/root': non-directory"));
}

#[test]
fn with_subject_keeps_an_invalid_operation_unrouted_for_generic_scope() {
    let inner = Error::build_invalid_operation_error("non-directory");

    let error = with_subject(
        inner,
        DirectoryScope::Generic,
        "test root",
        Path::new("/tmp/root"),
    );

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.rule(), None);
    assert!(error
        .format_user_message()
        .contains("Failed to open test root '/tmp/root': non-directory"));
}

#[test]
fn with_subject_leaves_every_other_error_kind_unchanged() {
    let inner = Error::build_io_error("disk gone");

    let error = with_subject(
        inner,
        DirectoryScope::Generic,
        "test root",
        Path::new("/tmp/root"),
    );

    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(error.format_user_message(), "disk gone");
}
