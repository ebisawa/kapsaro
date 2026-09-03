// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the staged write residue diagnostics of the doctor command.
//! Covers a clean tree, a staged directory, a staged document, the removal a
//! finding offers and a search that could not read the whole tree.

use std::path::Path;

use tempfile::TempDir;

use super::{build_residue_checks, check_local_state_write_residue, search_residue, ResidueLimits};
use crate::service::doctor::types::{DoctorCheck, DoctorStatus, LocalStateHome};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{DirectoryFd, DirectoryScope};
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::{create_local_state_dir, local_state_temp_dir, write_local_state_file};

const RESIDUE_RULE: &str = "W_LOCAL_STATE_WRITE_RESIDUE";
const STAGED_DIR: &str = ".tmp-3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const STAGED_FILE: &str = ".public.json.tmp.3f2504e0-4f89-41d3-9a0c-0305e82c3301";

fn opened_dir(home: &TempDir) -> AnchoredDir {
    AnchoredDir::open(home.path(), DirectoryScope::LocalState, "local state root").unwrap()
}

fn opened_home(home: &TempDir) -> LocalStateHome {
    LocalStateHome::Opened(opened_dir(home))
}

/// The checks one search produces, under bounds a test can reach.
fn residue_checks(home: &TempDir, limits: ResidueLimits) -> Vec<DoctorCheck> {
    let root = opened_dir(home);
    build_residue_checks(root.path(), &search_residue(&root, limits))
}

fn create_member_key_dirs(home: &Path) {
    create_local_state_dir(&home.join("keys"));
    create_local_state_dir(&home.join("keys/alice"));
    create_local_state_dir(&home.join("keys/alice/kid"));
}

#[test]
fn test_a_tree_with_no_staged_entry_is_reported_as_clean() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_member_key_dirs(home.path());
    write_local_state_file(&home.path().join("keys/alice/kid/public.json"), "{}");

    let checks = check_local_state_write_residue(&opened_home(&home));

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].id, "local_state.write_residue");
    assert_eq!(checks[0].status, DoctorStatus::Ok);
    assert_eq!(
        checks[0].message,
        "No unfinished write left an entry behind"
    );
}

/// A key directory an interrupted `key new` staged blocks every later command
/// that reads the member namespace, so it is named before one of them refuses.
#[test]
fn test_a_staged_directory_is_reported_with_its_removal() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_member_key_dirs(home.path());
    let staged = home.path().join("keys/alice").join(STAGED_DIR);
    create_local_state_dir(&staged);

    let checks = check_local_state_write_residue(&opened_home(&home));

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Warn);
    assert_eq!(
        checks[0].message,
        "Local state holds an entry an unfinished write staged"
    );
    assert_eq!(checks[0].rule.as_deref(), Some(RESIDUE_RULE));
    assert!(
        checks[0]
            .reason_line()
            .is_some_and(|reason| reason.contains("rm -r") && reason.contains(STAGED_DIR)),
        "{checks:#?}"
    );
    assert_eq!(
        checks[0].next_action.as_deref(),
        Some(
            "inspect the staged entry and remove it once no kapsaro command is running and its \
             contents are no longer needed"
        )
    );
}

/// A document staged beside the one it was replacing sits one level deeper than
/// a staged directory, so the search has to reach inside a key directory.
#[test]
fn test_a_staged_document_inside_a_key_directory_is_reported() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_member_key_dirs(home.path());
    write_local_state_file(&home.path().join("keys/alice/kid").join(STAGED_FILE), "{}");

    let checks = check_local_state_write_residue(&opened_home(&home));

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Warn);
    assert!(
        checks[0].subject.as_str().contains(STAGED_FILE),
        "{checks:#?}"
    );
}

/// A search that spends its entry budget leaves part of the tree unread, and a
/// staged entry among what it never reached would go unreported, so the result
/// says the tree was not searched.
#[test]
fn test_a_search_stopped_by_the_entry_budget_is_reported_as_unsearched() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_local_state_dir(&home.path().join("keys"));
    write_local_state_file(&home.path().join("keys").join(STAGED_FILE), "{}");

    let checks = residue_checks(
        &home,
        ResidueLimits {
            max_entries: 1,
            ..ResidueLimits::DEFAULT
        },
    );

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].id, "local_state.write_residue");
    assert_eq!(checks[0].status, DoctorStatus::Skip);
    assert_eq!(
        checks[0].message,
        "Local state was not searched for staged entries across the whole tree"
    );
    assert!(
        checks[0]
            .reason_line()
            .is_some_and(|reason| reason.contains("more than 1 entries")),
        "{checks:#?}"
    );
}

/// A tree deeper than the search reads holds levels it never saw, so the result
/// says the tree was not searched rather than that nothing was staged.
#[test]
fn test_a_search_stopped_by_the_depth_bound_is_reported_as_unsearched() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_member_key_dirs(home.path());
    write_local_state_file(&home.path().join("keys/alice/kid").join(STAGED_FILE), "{}");

    let checks = residue_checks(
        &home,
        ResidueLimits {
            max_depth: 2,
            ..ResidueLimits::DEFAULT
        },
    );

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Skip);
    assert!(
        checks[0]
            .reason_line()
            .is_some_and(|reason| reason.contains("deeper than 2 levels")),
        "{checks:#?}"
    );
}

/// What the search did reach is worth reporting on its own, so a staged entry
/// it found is named with its removal. The part it never read is named beside
/// it: an operator who removed only what was listed would otherwise take the
/// listing for the whole of what is staged.
#[test]
fn test_a_staged_entry_found_before_the_search_stopped_is_reported_with_the_unread_part() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_member_key_dirs(home.path());
    create_local_state_dir(&home.path().join(STAGED_DIR));

    let checks = residue_checks(
        &home,
        ResidueLimits {
            max_depth: 1,
            ..ResidueLimits::DEFAULT
        },
    );

    assert_eq!(checks.len(), 2, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Warn);
    assert!(
        checks[0].subject.as_str().contains(STAGED_DIR),
        "{checks:#?}"
    );
    assert_eq!(checks[1].status, DoctorStatus::Skip);
    assert_eq!(
        checks[1].message,
        "Local state was not searched for staged entries across the whole tree"
    );
}

/// The removal clears an entry that may belong to a write still running, so the
/// finding says what has to be true before it is safe to run.
#[test]
fn test_a_staged_entry_removal_names_the_condition_it_is_safe_under() {
    let _guard = LocalStateWarningGuard::new();
    let home = local_state_temp_dir();
    create_member_key_dirs(home.path());
    let staged = home.path().join("keys/alice").join(STAGED_DIR);
    create_local_state_dir(&staged);

    let checks = check_local_state_write_residue(&opened_home(&home));

    let reason = checks[0].reason_line().unwrap();
    assert!(
        reason.contains("no other kapsaro command is running"),
        "{reason}"
    );
    assert!(
        checks[0]
            .next_action
            .as_deref()
            .is_some_and(|action| action.contains("no kapsaro command is running")),
        "{checks:#?}"
    );
}

/// A root that never opened is already reported as unopened by the permission
/// checks, so the search adds nothing rather than naming the same condition
/// under a second identifier.
#[test]
fn test_an_unopened_root_produces_no_check() {
    let _guard = LocalStateWarningGuard::new();

    let checks = check_local_state_write_residue(&LocalStateHome::Missing);

    assert!(checks.is_empty(), "{checks:#?}");
}
