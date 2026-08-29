// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local state permission diagnostics for the doctor command.
//! Turns every entry and ancestor another user can reach into one check.

use std::path::Path;

use crate::app::doctor::types::{
    DoctorCategory, DoctorCheck, DoctorStatus, DoctorSubject, LocalStateHome,
};
use crate::error::{LOCAL_STATE_ANCESTOR_OWNER_RULE, LOCAL_STATE_PERMISSIONS_RULE};
use crate::support::fs::permission::{
    collect_local_state_tree_violations, walk_local_state_ancestry, AncestorOwnerFinding,
    LocalStateAncestryScan, PermissionViolation, PermissionViolationKind,
};
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};

const CHECK_ID: &str = "local_state.permissions";
const ANCESTOR_OWNER_CHECK_ID: &str = "local_state.ancestor_owner";

/// One reading of the chain of directories leading to the local state root.
///
/// The permission verdict and the ancestor-ownership finding are two questions
/// about the same directories, and both are answered from the one `stat` the
/// walk takes of each. Walking a second time would cost another pass and give
/// the two answers a chance to describe different trees, so the chain is read
/// once here and each check takes the view it needs.
pub(super) struct LocalStateAncestry(std::result::Result<LocalStateAncestryScan, String>);

impl LocalStateAncestry {
    pub(super) fn walk(base_dir: &Path) -> Self {
        Self(walk_local_state_ancestry(base_dir))
    }

    /// Every exposed ancestor the walk found.
    ///
    /// A chain that could not be resolved at all is not a finding about any one
    /// directory, and is reported through [`Self::unresolvable_reason`] instead.
    fn violations(&self) -> &[PermissionViolation] {
        match &self.0 {
            Ok(scan) => &scan.violations,
            Err(_) => &[],
        }
    }

    /// Why the chain could not be resolved at all, when it could not be.
    fn unresolvable_reason(&self) -> Option<&str> {
        self.0.as_ref().err().map(String::as_str)
    }

    /// Every ancestor a third account owns, or why the question went unanswered.
    ///
    /// An ancestor the walk could not stat is exactly the one that may belong to
    /// somebody else, so a walk that did not reach every directory answers
    /// nothing rather than answering from the part it did reach.
    fn owners(&self) -> std::result::Result<&[AncestorOwnerFinding], &str> {
        let scan = self.0.as_ref().map_err(String::as_str)?;
        match &scan.unreadable {
            Some(reason) => Err(reason.as_str()),
            None => Ok(&scan.owners),
        }
    }
}

/// Report every local state entry and ancestor directory another user can reach.
///
/// The ancestry is inspected even when the root itself cannot be opened,
/// because an ancestor another user can write is why the root may be missing or
/// wrong in the first place.
pub(super) fn check_local_state_permissions(
    base_dir: &Path,
    home: &LocalStateHome,
    ancestry: &LocalStateAncestry,
) -> Vec<DoctorCheck> {
    let mut checks = ancestry_violation_checks(base_dir, ancestry);
    if let Some(opened) = home.opened() {
        checks.extend(
            collect_local_state_tree_violations(opened)
                .iter()
                .map(build_violation_check),
        );
    }
    append_tree_scan_verdict(base_dir, home, &mut checks);
    checks
}

/// One check per exposed ancestor, or the walk's own failure named against the
/// root it started from.
fn ancestry_violation_checks(base_dir: &Path, ancestry: &LocalStateAncestry) -> Vec<DoctorCheck> {
    if let Some(reason) = ancestry.unresolvable_reason() {
        return vec![build_permission_check(
            PermissionViolationKind::UnresolvableAncestry,
            DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
            reason,
        )];
    }
    ancestry
        .violations()
        .iter()
        .map(build_violation_check)
        .collect()
}

/// Say what the walk of the tree below the root settled, once its findings are in.
///
/// A clean ancestry only stands for the whole of local state when the tree
/// below the root was walked. A root that never opened leaves every entry
/// uninspected, and answering owner-only there would let a consumer read the
/// result as a tree that passed.
///
/// The same holds when the ancestry did produce findings: those name the path
/// to the root and say nothing about what the root holds, so the tree that was
/// never walked is still reported as uninspected alongside them.
fn append_tree_scan_verdict(base_dir: &Path, home: &LocalStateHome, checks: &mut Vec<DoctorCheck>) {
    match unscanned_tree_reason(home) {
        Some(reason) => checks.push(build_unscanned_check(base_dir).with_reason(reason)),
        None if checks.is_empty() => checks.push(build_owner_only_check(base_dir)),
        None => {}
    }
}

/// Why the tree below the root went uninspected, when it did.
fn unscanned_tree_reason(home: &LocalStateHome) -> Option<String> {
    match home {
        LocalStateHome::Opened(_) => None,
        LocalStateHome::Missing => {
            Some("the local state root does not exist, so no entry was inspected".to_string())
        }
        LocalStateHome::Unavailable { reason } => Some(reason.clone()),
    }
}

fn build_unscanned_check(base_dir: &Path) -> DoctorCheck {
    DoctorCheck::skip(
        CHECK_ID,
        DoctorCategory::LocalState,
        DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
        "Local state permissions were not checked",
    )
}

fn build_owner_only_check(base_dir: &Path) -> DoctorCheck {
    DoctorCheck::ok(
        CHECK_ID,
        DoctorCategory::LocalState,
        DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
        "Local state permissions are owner-only",
    )
}

/// One check per violation, at the status the violation itself carries.
///
/// Local state another account owns is not protected whatever its mode says:
/// that account can rewrite or replace it at any moment, and the operator
/// cannot repair it from their own session, so the exit code has to carry it.
/// Everything else is a warning. A replaced entry happens during an ordinary
/// concurrent write, and an entry or an ancestor the walk could not read means
/// the check did not run rather than that it found something — failing on those
/// would take the diagnosis away from exactly the environments that need it.
fn build_violation_check(violation: &PermissionViolation) -> DoctorCheck {
    build_permission_check(
        violation.kind(),
        violation_subject(violation),
        violation.message(),
    )
}

/// The one shape every permission finding takes, whatever produced it.
fn build_permission_check(
    kind: PermissionViolationKind,
    subject: DoctorSubject,
    reason: &str,
) -> DoctorCheck {
    DoctorCheck::new(
        CHECK_ID,
        DoctorCategory::LocalState,
        violation_status(kind),
        subject,
        violation_message(kind),
    )
    .with_reason(reason)
    .with_next_action(violation_next_action(kind))
    .with_rule(Some(LOCAL_STATE_PERMISSIONS_RULE))
}

fn violation_status(kind: PermissionViolationKind) -> DoctorStatus {
    match kind {
        PermissionViolationKind::ForeignOwner => DoctorStatus::Fail,
        _ => DoctorStatus::Warn,
    }
}

/// Report every ancestor directory a third account owns.
///
/// Ownership above the local state root is left unchecked on purpose, because
/// the path there is arranged by whoever administers the machine rather than by
/// kapsaro. It is still worth naming once, so this stands as its own check and
/// never moves the permission verdict.
///
/// A walk that could not read every ancestor is reported as a check that did
/// not run. Answering that the ancestry is fine would let the one directory the
/// walk could not inspect pass as one it approved.
pub(super) fn check_local_state_ancestor_owner(
    base_dir: &Path,
    ancestry: &LocalStateAncestry,
) -> Vec<DoctorCheck> {
    let findings = match ancestry.owners() {
        Err(reason) => {
            return vec![build_unscanned_ancestor_owner_check(base_dir).with_reason(reason)];
        }
        Ok(findings) => findings,
    };
    if findings.is_empty() {
        return vec![DoctorCheck::ok(
            ANCESTOR_OWNER_CHECK_ID,
            DoctorCategory::LocalState,
            DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
            "Local state ancestors are owned by you or by the machine administrator",
        )];
    }
    findings.iter().map(build_ancestor_owner_check).collect()
}

fn build_unscanned_ancestor_owner_check(base_dir: &Path) -> DoctorCheck {
    DoctorCheck::skip(
        ANCESTOR_OWNER_CHECK_ID,
        DoctorCategory::LocalState,
        DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
        "Local state ancestor ownership was not checked",
    )
}

fn build_ancestor_owner_check(finding: &AncestorOwnerFinding) -> DoctorCheck {
    DoctorCheck::warn_with_reason_and_next_action(
        ANCESTOR_OWNER_CHECK_ID,
        DoctorCategory::LocalState,
        DoctorSubject::Path(format_finding_path(finding.path())),
        "Local state ancestor directory is owned by another account",
        format!(
            "Ancestor directory {} is owned by uid {}, which is neither the current user nor the \
             machine administrator; that account can replace the local state path",
            format_finding_path(finding.path()),
            finding.owner(),
        ),
        "move local state below a directory you own, or select another local state root with \
         --home or KAPSARO_HOME",
    )
    .with_rule(Some(LOCAL_STATE_ANCESTOR_OWNER_RULE))
}

/// Name the path the operator has to repair.
///
/// One spelling for every kind: the finding is read where the working directory
/// is the reader's own frame, and the path that is the working directory falls
/// back to its full form rather than to a bare dot.
fn violation_subject(violation: &PermissionViolation) -> DoctorSubject {
    DoctorSubject::Path(format_finding_path(violation.path()))
}

fn violation_message(kind: PermissionViolationKind) -> &'static str {
    match kind {
        PermissionViolationKind::InsecureMode => "Local state entry is reachable by other users",
        PermissionViolationKind::ForeignOwner => "Local state entry is owned by another user",
        PermissionViolationKind::Unreadable => "Local state entry permissions could not be checked",
        PermissionViolationKind::UndecodableName => {
            "Local state holds an entry name kapsaro cannot decode"
        }
        PermissionViolationKind::UnexpectedEntryType => {
            "Local state holds an entry of a type kapsaro never writes"
        }
        PermissionViolationKind::ReplacedEntry => {
            "Local state entry was replaced while its permissions were being checked"
        }
        PermissionViolationKind::UnreadableAncestor => {
            "Local state ancestor directory permissions could not be checked"
        }
        PermissionViolationKind::InsecureAncestor => {
            "Local state ancestor directory is writable by other users"
        }
        PermissionViolationKind::UnresolvableAncestry => {
            "Local state ancestry could not be resolved"
        }
        PermissionViolationKind::IncompleteScan => {
            "Local state permissions were not checked across the whole tree"
        }
    }
}

/// A shared parent has to stay readable, so only its write bits change.
const ANCESTOR_WRITE_ACCESS_ACTION: &str =
    "remove group and other write access from the local state ancestor directory";

const ANCESTOR_READABLE_ACTION: &str =
    "make the local state ancestor directory readable, or select another local state root with \
     --home or KAPSARO_HOME";

const ANCESTRY_RESOLVABLE_ACTION: &str =
    "make every directory on the path to the local state root resolvable, or select another local \
     state root with --home or KAPSARO_HOME";

/// A scan that ran out of budget needs the tree itself reduced first.
const REDUCE_TREE_ACTION: &str = "remove what kapsaro did not write below the local state root";

const INSPECT_FOREIGN_ENTRY_ACTION: &str =
    "inspect the entry kapsaro did not write and remove it if it is not needed";

/// The walk saw two different entries under one name, so what is there now was
/// never checked. Another run is what settles it.
const RERUN_ACTION: &str =
    "find out what is writing below the local state root, then run the check again";

const ENTRY_READABLE_ACTION: &str =
    "make the local state entry readable so its permissions can be checked";

const OWNER_ONLY_ACTION: &str = "restrict local state permissions to owner only";

/// Changing the mode is not the operator's to make here: the entry belongs to
/// somebody else, who can set it back at any time.
const TAKE_OWNERSHIP_ACTION: &str =
    "take ownership of the local state entry, or select another local state root with --home or \
     KAPSARO_HOME";

/// Name the repair that fits the entry.
fn violation_next_action(kind: PermissionViolationKind) -> &'static str {
    match kind {
        PermissionViolationKind::InsecureAncestor => ANCESTOR_WRITE_ACCESS_ACTION,
        PermissionViolationKind::UnreadableAncestor => ANCESTOR_READABLE_ACTION,
        PermissionViolationKind::UnresolvableAncestry => ANCESTRY_RESOLVABLE_ACTION,
        PermissionViolationKind::IncompleteScan => REDUCE_TREE_ACTION,
        PermissionViolationKind::UndecodableName | PermissionViolationKind::UnexpectedEntryType => {
            INSPECT_FOREIGN_ENTRY_ACTION
        }
        PermissionViolationKind::ReplacedEntry => RERUN_ACTION,
        PermissionViolationKind::Unreadable => ENTRY_READABLE_ACTION,
        PermissionViolationKind::InsecureMode => OWNER_ONLY_ACTION,
        PermissionViolationKind::ForeignOwner => TAKE_OWNERSHIP_ACTION,
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/app_doctor_local_state_permissions_test.rs"]
mod tests;
