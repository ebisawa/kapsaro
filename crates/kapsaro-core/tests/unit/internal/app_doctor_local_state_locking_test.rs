// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the lock effectiveness diagnostics of the doctor command.
//! Covers the verdict on real storage and the wording of every weak finding.

use tempfile::TempDir;

use super::{
    check_local_state_locking, check_workspace_locking, weak_locking_message, weak_locking_reason,
    WeakLocking,
};
use crate::app::doctor::types::{DoctorCategory, DoctorStatus, DoctorSubject, LocalStateHome};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::with_exclusive_locked_directory;
use crate::support::fs::relative::{open_dir_following, DirectoryScope};
use crate::support::path::format_path_relative_to_cwd;

/// Storage a test runs on arbitrates locks and belongs to this machine, so the
/// measurement passes and says nothing an operator has to act on.
#[test]
fn test_locking_reports_local_storage_as_effective() {
    let home = TempDir::new().unwrap();

    let opened = AnchoredDir::open(
        home.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();
    let checks = check_local_state_locking(home.path(), &LocalStateHome::Opened(opened));

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].id, "local_state.locking");
    assert_eq!(checks[0].category, DoctorCategory::LocalState);
    assert_eq!(checks[0].status, DoctorStatus::Ok, "{checks:#?}");
    assert_eq!(
        checks[0].subject,
        DoctorSubject::Path(format_path_relative_to_cwd(home.path()))
    );
}

/// The workspace is measured under its own identifier and category, so a
/// finding on one root is never read as a finding on the other.
#[test]
fn test_workspace_locking_is_reported_under_the_workspace_category() {
    let workspace = TempDir::new().unwrap();
    let opened =
        AnchoredDir::open(workspace.path(), DirectoryScope::Generic, "workspace root").unwrap();

    let checks = check_workspace_locking(&opened);

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].id, "workspace.locking");
    assert_eq!(checks[0].category, DoctorCategory::Workspace);
}

/// The measurement follows the descriptor the run bound to rather than the name
/// it was opened through.
///
/// The name is taken over by a regular file, which nothing can lock or ask about
/// a mount: a measurement that resolved the name again would report that it could
/// not be made, so an answer at all is the answer coming from the descriptor.
#[test]
fn test_workspace_locking_measures_the_directory_the_descriptor_holds() {
    let parent = TempDir::new().unwrap();
    let workspace = parent.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let opened = AnchoredDir::open(&workspace, DirectoryScope::Generic, "workspace root").unwrap();
    std::fs::rename(&workspace, parent.path().join("moved")).unwrap();
    std::fs::write(&workspace, b"not a directory").unwrap();

    let checks = check_workspace_locking(&opened);

    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0].status, DoctorStatus::Ok, "{checks:#?}");
}

/// A lock already held would refuse the second take whatever the filesystem
/// does, so the measurement reports that it did not run rather than passing.
#[test]
fn test_locking_skips_a_directory_somebody_else_holds() {
    let home = TempDir::new().unwrap();
    let directory = open_dir_following(home.path(), DirectoryScope::LocalState).unwrap();

    let checks = with_exclusive_locked_directory(&directory, |_| {
        let opened = AnchoredDir::open(
            home.path(),
            DirectoryScope::LocalState,
            "test local state root",
        )?;
        Ok::<_, crate::Error>(check_local_state_locking(
            home.path(),
            &LocalStateHome::Opened(opened),
        ))
    })
    .unwrap();

    assert_eq!(checks[0].status, DoctorStatus::Skip, "{checks:#?}");
    assert_eq!(checks[0].message, "Directory locking was not measured");
    assert!(
        checks[0]
            .reason_line()
            .is_some_and(|reason| reason.contains("already held")),
        "{checks:#?}"
    );
    assert_eq!(checks[0].rule, None);
}

/// A root that is not there cannot be measured, and the reason travels with the
/// check so the operator is not left matching it up with another finding.
#[test]
fn test_locking_skips_a_directory_it_cannot_open() {
    let home = TempDir::new().unwrap();

    let missing = home.path().join("missing");
    let checks = check_local_state_locking(&missing, &LocalStateHome::Missing);

    assert_eq!(checks[0].status, DoctorStatus::Skip, "{checks:#?}");
    assert!(
        checks[0]
            .reason_line()
            .is_some_and(|reason| !reason.is_empty()),
        "{checks:#?}"
    );
}

#[cfg(unix)]
#[test]
fn test_local_state_locking_measures_the_opened_home_after_path_swap() {
    let parent = TempDir::new().unwrap();
    let home = parent.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let opened =
        AnchoredDir::open(&home, DirectoryScope::LocalState, "test local state root").unwrap();
    std::fs::rename(&home, parent.path().join("opened")).unwrap();
    std::fs::write(&home, b"replacement").unwrap();

    let checks = check_local_state_locking(&home, &LocalStateHome::Opened(opened));

    assert_eq!(checks[0].status, DoctorStatus::Ok, "{checks:#?}");
}

#[test]
fn test_local_state_locking_skips_an_unavailable_home_with_its_reason() {
    let home = TempDir::new().unwrap().path().join("unavailable");
    let checks = check_local_state_locking(
        &home,
        &LocalStateHome::Unavailable {
            reason: "unsafe local state path".to_string(),
        },
    );

    assert_eq!(checks[0].status, DoctorStatus::Skip, "{checks:#?}");
    assert_eq!(
        checks[0].reason_line().as_deref(),
        Some("unsafe local state path")
    );
}

/// Every weak finding has to say what an operator stands to lose, because a
/// write that lands on top of another leaves no trace of the one it replaced.
#[test]
fn test_every_weak_finding_names_the_change_that_would_be_lost() {
    for kind in [
        WeakLocking::SharedStorage,
        WeakLocking::UnknownStorage,
        WeakLocking::Ineffective,
        WeakLocking::Unsupported,
    ] {
        let reason = weak_locking_reason(kind);
        assert!(reason.contains("replace"), "{kind:?}: {reason}");
        assert!(!weak_locking_message(kind).is_empty(), "{kind:?}");
    }
}
