// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the local state permission diagnostics of the doctor command.
//! Covers the owner-only state and the checks each violation turns into.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::TempDir;

use super::{
    build_permission_check, check_local_state_ancestor_owner, check_local_state_permissions,
    LocalStateAncestry,
};
use crate::service::doctor::types::{DoctorCheck, DoctorStatus, DoctorSubject, LocalStateHome};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::permission::PermissionViolationKind;
use crate::support::fs::relative::DirectoryScope;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::{
    create_local_state_dir, local_state_temp_dir, permission_denial_can_be_staged, with_temp_cwd,
    write_local_state_file,
};

const PERMISSIONS_RULE: &str = "W_LOCAL_STATE_PERMISSIONS";

fn open_home(home: &TempDir) -> AnchoredDir {
    AnchoredDir::open(home.path(), DirectoryScope::LocalState, "local state root").unwrap()
}

fn subject_path(path: &Path) -> DoctorSubject {
    DoctorSubject::Path(format_path_relative_to_cwd(path))
}

/// Both checks read one walk of the ancestry, which each test takes here.
fn permission_checks(base_dir: &Path, home: &LocalStateHome) -> Vec<DoctorCheck> {
    check_local_state_permissions(base_dir, home, &LocalStateAncestry::walk(base_dir))
}

fn ancestor_owner_checks(base_dir: &Path) -> Vec<DoctorCheck> {
    check_local_state_ancestor_owner(base_dir, &LocalStateAncestry::walk(base_dir))
}

#[test]
fn test_local_state_permissions_report_an_owner_only_tree_as_ok() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_local_state_dir(&home.path().join("keys"));
    write_local_state_file(&home.path().join("config.toml"), "member_handle = \"a\"\n");
    let opened = open_home(&home);

    let checks = permission_checks(home.path(), &LocalStateHome::Opened(opened));

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].id, "local_state.permissions");
    assert_eq!(checks[0].status, DoctorStatus::Ok);
    assert_eq!(checks[0].message, "Local state permissions are owner-only");
    assert_eq!(checks[0].subject, subject_path(home.path()));
}

#[test]
fn test_local_state_permissions_report_one_check_per_reachable_entry() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    let keys = home.path().join("keys");
    create_local_state_dir(&keys);
    let document = keys.join("private.json");
    write_local_state_file(&document, "{}");
    fs::set_permissions(&document, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o755)).unwrap();
    let opened = open_home(&home);

    let checks = permission_checks(home.path(), &LocalStateHome::Opened(opened));

    assert_eq!(checks.len(), 2, "{checks:#?}");
    assert!(checks.iter().all(|check| {
        check.id == "local_state.permissions"
            && check.status == DoctorStatus::Warn
            && check.message == "Local state entry is reachable by other users"
            && check.rule.as_deref() == Some(PERMISSIONS_RULE)
            && check.next_action.as_deref()
                == Some("restrict local state permissions to owner only")
    }));
    assert!(checks
        .iter()
        .any(|check| check.subject == subject_path(&keys)));
    assert!(checks
        .iter()
        .any(|check| check.subject == subject_path(&document)));
}

/// The reason repeats the message the command would print as a warning, so the
/// operator reads the same repair in the report and on stderr.
#[test]
fn test_local_state_permissions_carry_the_violation_message_as_the_reason() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    let keys = home.path().join("keys");
    create_local_state_dir(&keys);
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o750)).unwrap();
    let opened = open_home(&home);

    let checks = permission_checks(home.path(), &LocalStateHome::Opened(opened));

    let reason = checks[0].reason_line().unwrap();
    assert!(reason.contains("0750"), "{reason}");
    assert!(reason.contains("chmod 0700"), "{reason}");
}

/// Local state a third account owns has to reach the exit code: that account
/// can rewrite the entry whenever it likes, and the operator cannot repair it
/// from their own session. This is what a symlink or a special file another
/// account left in local state is reported as. No test can create an entry
/// owned elsewhere, so the finding is judged from the kind that names it.
#[test]
fn test_local_state_permissions_report_a_foreign_owner_as_a_failure() {
    let check = build_permission_check(
        PermissionViolationKind::ForeignOwner,
        subject_path(Path::new("/local/state/link")),
        "is owned by uid 1234, not by the current user",
    );

    assert_eq!(check.status, DoctorStatus::Fail);
    assert_eq!(check.message, "Local state entry is owned by another user");
    assert_eq!(check.rule.as_deref(), Some(PERMISSIONS_RULE));
    assert_eq!(
        check.next_action.as_deref(),
        Some(
            "take ownership of the local state entry, or select another local state root with \
             --home or KAPSARO_HOME"
        )
    );
}

/// A directory another user can write lets them replace the whole local state
/// tree, and the repair differs from the one an entry needs.
#[test]
fn test_local_state_permissions_report_a_group_writable_ancestor() {
    let _guard = LocalStateWarningGuard::new();
    let outer = local_state_temp_dir();
    let shared = outer.path().join("shared");
    create_local_state_dir(&shared);
    let home = shared.join("home");
    create_local_state_dir(&home);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let opened = AnchoredDir::open(&home, DirectoryScope::LocalState, "local state root").unwrap();

    let checks = permission_checks(&home, &LocalStateHome::Opened(opened));

    let ancestor = checks
        .iter()
        .find(|check| check.message == "Local state ancestor directory is writable by other users")
        .unwrap_or_else(|| panic!("{checks:#?}"));
    assert_eq!(ancestor.status, DoctorStatus::Warn);
    assert_eq!(ancestor.rule.as_deref(), Some(PERMISSIONS_RULE));
    assert_eq!(
        ancestor.next_action.as_deref(),
        Some("remove group and other write access from the local state ancestor directory")
    );
    assert!(ancestor
        .reason_line()
        .is_some_and(|reason| reason.contains("chmod go-w")));
}

/// A scan that stopped at its bounds covered only part of the tree, so the
/// report names what stayed unchecked rather than calling the tree owner-only.
#[test]
fn test_local_state_permissions_report_a_scan_that_stopped_before_the_whole_tree() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    let mut nested = home.path().to_path_buf();
    for level in 0..7 {
        nested = nested.join(format!("level-{level}"));
        create_local_state_dir(&nested);
    }
    let opened = open_home(&home);

    let checks = permission_checks(home.path(), &LocalStateHome::Opened(opened));

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Warn);
    assert_eq!(
        checks[0].message,
        "Local state permissions were not checked across the whole tree"
    );
    assert_eq!(checks[0].rule.as_deref(), Some(PERMISSIONS_RULE));
    assert_eq!(
        checks[0].next_action.as_deref(),
        Some("remove what kapsaro did not write below the local state root")
    );
}

/// An ancestry the walk could not resolve at all is reported through the same
/// check id as the unscanned-tree verdict that follows it, so both findings
/// have to name the root the same way. Naming the working directory itself is
/// what tells the two path functions apart: one collapses it to `.`, the other
/// falls back to the full path.
#[test]
fn test_local_state_permissions_format_an_unresolvable_ancestry_like_the_rest_of_the_check() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    let base_dir = home.path().canonicalize().unwrap();

    let checks = with_temp_cwd(&base_dir, || {
        check_local_state_permissions(
            &base_dir,
            &LocalStateHome::Missing,
            &LocalStateAncestry(Err("cannot resolve ancestry".to_string())),
        )
    });

    assert_eq!(checks.len(), 2, "{checks:#?}");
    let unresolvable = checks
        .iter()
        .find(|check| check.message == "Local state ancestry could not be resolved")
        .unwrap_or_else(|| panic!("{checks:#?}"));
    let unscanned = checks
        .iter()
        .find(|check| check.status == DoctorStatus::Skip)
        .unwrap_or_else(|| panic!("{checks:#?}"));
    assert_eq!(unresolvable.subject, DoctorSubject::Path(".".to_string()));
    assert_eq!(unresolvable.subject, unscanned.subject);
}

/// A root that never opened leaves every entry uninspected, so the result says
/// the check did not run rather than passing an unscanned tree as owner-only.
#[test]
fn test_local_state_permissions_skip_a_root_that_never_opened() {
    let _guard = LocalStateWarningGuard::new();
    let outer = local_state_temp_dir();
    let safe = outer.path().join("safe");
    create_local_state_dir(&safe);

    let checks = permission_checks(&safe.join("missing-home"), &LocalStateHome::Missing);

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Skip);
    assert_eq!(
        checks[0].message,
        "Local state permissions were not checked"
    );
}

/// An unsafe root carries its own explanation, so the skipped check repeats the
/// reason instead of leaving the operator to match it up with another finding.
#[test]
fn test_local_state_permissions_skip_an_unavailable_root_with_its_reason() {
    let _guard = LocalStateWarningGuard::new();
    let outer = local_state_temp_dir();
    let safe = outer.path().join("safe");
    create_local_state_dir(&safe);
    let home = LocalStateHome::Unavailable {
        reason: "refusing to open symlink as directory".to_string(),
    };

    let checks = permission_checks(&safe.join("home"), &home);

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Skip);
    assert_eq!(
        checks[0].reason_line().as_deref(),
        Some("refusing to open symlink as directory")
    );
}

/// A temporary directory sits below paths the test account owns, and everything
/// from there up to `/` belongs to whoever administers the machine, so the
/// whole chain is one the operator has no reason to be told about.
#[test]
fn test_local_state_ancestor_owner_reports_an_administered_chain_as_ok() {
    let home = local_state_temp_dir();

    let checks = ancestor_owner_checks(home.path());

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].id, "local_state.ancestor_owner");
    assert_eq!(checks[0].status, DoctorStatus::Ok);
    assert_eq!(
        checks[0].message,
        "Local state ancestors are owned by you or by the machine administrator"
    );
    assert_eq!(checks[0].subject, subject_path(home.path()));
    assert_eq!(checks[0].rule, None);
}

/// An ancestor the walk cannot look at is exactly the one that might belong to
/// somebody else, so the check says it did not run rather than passing the
/// chain it never inspected.
#[test]
fn test_local_state_ancestor_owner_skips_an_ancestry_it_cannot_walk() {
    if !permission_denial_can_be_staged(
        "test_local_state_ancestor_owner_skips_an_ancestry_it_cannot_walk",
    ) {
        return;
    }

    let outer = local_state_temp_dir();
    let blocked = outer.path().join("blocked");
    create_local_state_dir(&blocked);
    let home = blocked.join("home");
    create_local_state_dir(&home);
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();

    let checks = ancestor_owner_checks(&home);

    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].id, "local_state.ancestor_owner");
    assert_eq!(checks[0].status, DoctorStatus::Skip);
    assert_eq!(
        checks[0].message,
        "Local state ancestor ownership was not checked"
    );
    assert!(
        checks[0]
            .reason_line()
            .is_some_and(|reason| reason.contains("local state ancestr")),
        "{checks:#?}"
    );
}

/// The ancestry is the reason an unopenable root is worth reporting, so it is
/// inspected even when the root itself never opened.
#[test]
fn test_local_state_permissions_inspect_the_ancestry_of_an_unopened_root() {
    let _guard = LocalStateWarningGuard::new();
    let outer = local_state_temp_dir();
    let shared = outer.path().join("shared");
    create_local_state_dir(&shared);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

    let checks = permission_checks(&shared.join("missing-home"), &LocalStateHome::Missing);

    assert!(checks.iter().any(|check| {
        check.status == DoctorStatus::Warn
            && check.message == "Local state ancestor directory is writable by other users"
            && check.subject == subject_path(&fs::canonicalize(&shared).unwrap())
    }));
}

/// An ancestor finding names the path to the root and says nothing about what
/// the root holds, so a reader still has to be told the tree went unwalked.
#[test]
fn test_local_state_permissions_report_an_unwalked_tree_beside_an_ancestor_finding() {
    let _guard = LocalStateWarningGuard::new();
    let outer = local_state_temp_dir();
    let shared = outer.path().join("shared");
    create_local_state_dir(&shared);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

    let checks = permission_checks(&shared.join("missing-home"), &LocalStateHome::Missing);

    assert!(
        checks.iter().any(|check| {
            check.status == DoctorStatus::Skip
                && check.message == "Local state permissions were not checked"
        }),
        "{checks:#?}"
    );
}
