// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Staged write residue diagnostics for the doctor command.
//! Finds entries an interrupted write left behind and names the removal.

use std::path::{Path, PathBuf};

use crate::error::LOCAL_STATE_WRITE_RESIDUE_RULE;
use crate::service::doctor::types::{DoctorCategory, DoctorCheck, DoctorSubject, LocalStateHome};
use crate::support::fs::relative::{
    is_write_staging_name, open_scanned_child_dir, scan_child_entries_at, ChildType, DirectoryFd,
    ScanBudget, ScannedChild,
};
use crate::support::path::format_finding_path;
use crate::support::shell::append_repair_command;

const CHECK_ID: &str = "local_state.write_residue";

/// How many levels below the local state root the search reads.
///
/// A write stages beside the entry it is about to publish, and the deepest
/// entry kapsaro writes is a key document three levels below the root, so a
/// staged one sits at the fourth.
const MAX_RESIDUE_DEPTH: usize = 4;

/// How many entries one search reads before it gives up.
///
/// A local state tree holds one directory per key, so a search that runs past
/// this is reading something kapsaro did not write and would keep the command
/// walking it for as long as it grows.
const MAX_RESIDUE_ENTRIES: usize = 1024;

/// Report every entry an unfinished write staged and never published.
///
/// Normal readers ignore internal staging names, so Doctor owns reporting the
/// residue and the recovery action.
pub(super) fn check_local_state_write_residue(home: &LocalStateHome) -> Vec<DoctorCheck> {
    let Some(root) = home.opened() else {
        // The root is already reported as unopened by the permission checks,
        // and repeating it here would name the same condition twice.
        return Vec::new();
    };
    let search = search_residue(root, ResidueLimits::DEFAULT);
    build_residue_checks(root.path(), &search)
}

/// Search the tree below `root` under the bounds `limits` names.
fn search_residue<D>(root: &D, limits: ResidueLimits) -> ResidueSearch
where
    D: DirectoryFd,
{
    let mut search = ResidueSearch::new(limits);
    search.walk(root, 0);
    search
}

/// Report every entry the search found, and whether it saw the whole tree.
///
/// A search that did not reach every entry says so whatever it found: the
/// entries it never read are the ones a staged entry would sit among, and an
/// operator who removes the ones that were reported would otherwise take the
/// listing for the complete one and leave the rest behind.
fn build_residue_checks(root: &Path, search: &ResidueSearch) -> Vec<DoctorCheck> {
    let mut checks: Vec<DoctorCheck> = search
        .found
        .iter()
        .map(|path| build_residue_check(path))
        .collect();
    if let Some(gap) = search.gap {
        checks.push(build_unsearched_check(root, gap, search.limits));
        return checks;
    }
    if checks.is_empty() {
        checks.push(DoctorCheck::ok(
            CHECK_ID,
            DoctorCategory::LocalState,
            DoctorSubject::Path(format_finding_path(root)),
            "No unfinished write left an entry behind",
        ));
    }
    checks
}

fn build_unsearched_check(root: &Path, gap: ResidueScanGap, limits: ResidueLimits) -> DoctorCheck {
    DoctorCheck::skip(
        CHECK_ID,
        DoctorCategory::LocalState,
        DoctorSubject::Path(format_finding_path(root)),
        "Local state was not searched for staged entries across the whole tree",
    )
    .with_reason(gap.describe(root, limits))
}

/// Name one staged entry and the removal that clears it.
///
/// The search reads the tree without holding the lock a write takes, so an
/// entry it names may belong to a write that is still running rather than to
/// one that was interrupted. The two look alike from outside, and removing the
/// staging of a write in progress destroys what that write was saving, so the
/// removal is offered together with the condition it is safe under.
fn build_residue_check(path: &Path) -> DoctorCheck {
    DoctorCheck::build_warning_with_reason_and_next_action(
        CHECK_ID,
        DoctorCategory::LocalState,
        DoctorSubject::Path(format_finding_path(path)),
        "Local state holds an entry an unfinished write staged",
        append_repair_command(
            &format!(
                "{} was staged by a write that never published it and may hold the only copy of \
                 what that write was saving. A write that is still running stages \
                 under a name of this shape too, so check that no other kapsaro command is \
                 running against this local state root before removing it",
                format_finding_path(path)
            ),
            "rm -r",
            path,
        ),
        "inspect the staged entry and remove it once no kapsaro command is running and its \
         contents are no longer needed",
    )
    .with_rule(Some(LOCAL_STATE_WRITE_RESIDUE_RULE))
}

/// The bounds one search runs under.
///
/// Carried as a value rather than read from the constants at each step, so the
/// search can be exercised at bounds a test reaches without building the tree
/// the real ones describe.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ResidueLimits {
    max_entries: usize,
    max_depth: usize,
}

impl ResidueLimits {
    const DEFAULT: Self = Self {
        max_entries: MAX_RESIDUE_ENTRIES,
        max_depth: MAX_RESIDUE_DEPTH,
    };
}

/// Why a search covered less than the whole tree.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ResidueScanGap {
    /// The entry budget ran out while entries were still unread.
    Entries,
    /// The tree goes deeper than the search reads.
    Depth,
    /// A directory on the way could not be listed or opened.
    Unreadable,
}

impl ResidueScanGap {
    /// Say what was left unread, so a reader knows what the answer covers.
    fn describe(self, root: &Path, limits: ResidueLimits) -> String {
        let cause = match self {
            Self::Entries => format!("holds more than {} entries", limits.max_entries),
            Self::Depth => format!("goes deeper than {} levels", limits.max_depth),
            Self::Unreadable => "holds a directory that could not be read".to_string(),
        };
        format!(
            "The local state tree below {} {}, so the search stopped before it had seen every \
             entry, and an entry an unfinished write staged among the ones it never read would \
             not be reported",
            format_finding_path(root),
            cause,
        )
    }
}

/// One bounded walk of the local state tree, collecting what it finds.
///
/// An entry whose own metadata could not be read is passed over rather than
/// reported: this search answers only whether a staged entry is present, and
/// such an entry is already a finding of the permission checks. A directory the
/// walk could not read at all, and a bound that ended it early, are recorded
/// instead, because both leave entries the search never saw.
struct ResidueSearch {
    found: Vec<PathBuf>,
    remaining_entries: usize,
    gap: Option<ResidueScanGap>,
    limits: ResidueLimits,
}

impl ResidueSearch {
    fn new(limits: ResidueLimits) -> Self {
        Self {
            found: Vec::new(),
            remaining_entries: limits.max_entries,
            gap: None,
            limits,
        }
    }

    /// Note what the search did not cover, keeping the first reason it met.
    fn mark_gap(&mut self, gap: ResidueScanGap) {
        self.gap.get_or_insert(gap);
    }

    fn walk<D>(&mut self, dir: &D, depth: usize)
    where
        D: DirectoryFd,
    {
        let scanned = match scan_child_entries_at(dir, ScanBudget::AtMost(self.remaining_entries)) {
            Ok(scanned) => scanned,
            Err(_) => {
                self.mark_gap(ResidueScanGap::Unreadable);
                return;
            }
        };
        if scanned.truncated {
            self.mark_gap(ResidueScanGap::Entries);
        }
        for child in scanned.entries {
            // A walk below one entry spends the budget the entries beside it
            // would have been read with, so the rest of this listing is left
            // unread rather than judged from what was already spent.
            if self.remaining_entries == 0 {
                self.mark_gap(ResidueScanGap::Entries);
                return;
            }
            self.remaining_entries -= 1;
            self.inspect(dir, child, depth);
        }
    }

    /// Judge one entry, then walk into it when a staged entry could still sit
    /// below.
    fn inspect<D>(&mut self, dir: &D, child: ScannedChild, depth: usize)
    where
        D: DirectoryFd,
    {
        let ScannedChild::Inspected {
            name, child_type, ..
        } = child
        else {
            return;
        };
        if name.decoded().is_some_and(is_write_staging_name) {
            self.found.push(name.path_under(dir));
            return;
        }
        if child_type != ChildType::Directory {
            return;
        }
        if depth + 1 >= self.limits.max_depth {
            self.mark_gap(ResidueScanGap::Depth);
            return;
        }
        match open_scanned_child_dir(dir, &name) {
            // A directory removed between the listing and the open holds
            // nothing now, so nothing was left unread with it.
            Ok(None) => {}
            Ok(Some(opened)) => self.walk(&opened, depth + 1),
            Err(_) => self.mark_gap(ResidueScanGap::Unreadable),
        }
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/service_doctor_local_state_staging_test.rs"]
mod service_doctor_local_state_staging_test;
