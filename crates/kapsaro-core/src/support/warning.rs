// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Warning collection helpers.
//! Keeps ordered warning lists deduplicated and collects local state warnings.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

pub(crate) fn push_unique_warning<T: PartialEq>(warnings: &mut Vec<T>, warning: T) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

/// Upper bound on the local state warnings held for one command.
///
/// A tree whose permissions are wrong throughout produces one warning per
/// entry, so the sink is capped rather than allowed to grow with the tree.
pub(crate) const MAX_LOCAL_STATE_WARNINGS: usize = 64;

/// Which rule one recorded local state warning belongs to.
///
/// The rule strings themselves live beside the error rules, so a warning taken
/// through the facade and the same finding reported by the diagnostic command
/// name one code.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum LocalStateWarningCode {
    Permissions,
}

/// One local state finding, kept as its parts rather than as a rendered line.
///
/// A caller that receives the path apart from the sentence can act on the entry
/// — filter it, repair it, log it — without parsing the wording back out.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct LocalStateWarning {
    code: LocalStateWarningCode,
    path: PathBuf,
    reason: String,
}

impl LocalStateWarning {
    pub(crate) fn new(code: LocalStateWarningCode, path: &Path, reason: String) -> Self {
        Self {
            code,
            path: path.to_path_buf(),
            reason,
        }
    }

    pub(crate) fn code(&self) -> LocalStateWarningCode {
        self.code
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}

/// The warnings one take carries, and how many it could not carry.
///
/// `dropped` counts distinct warnings the cap turned away, and is itself
/// capped, so it is a floor on what is missing rather than an exact total.
#[derive(Debug)]
pub(crate) struct LocalStateWarningBatch {
    pub(crate) warnings: Vec<LocalStateWarning>,
    pub(crate) dropped: usize,
}

/// The warnings held for one command and the distinct ones it could not hold.
///
/// The turned-away warnings are kept by value beside the held ones so a capped
/// report can say how much of the finding is missing instead of reading as the
/// whole of it, and so a repeat of one already turned away is not counted
/// again. That list carries the same cap: once it is full a further distinct
/// warning goes uncounted.
struct LocalStateWarningSink {
    warnings: Vec<LocalStateWarning>,
    dropped: Vec<LocalStateWarning>,
}

impl LocalStateWarningSink {
    const fn new() -> Self {
        Self {
            warnings: Vec::new(),
            dropped: Vec::new(),
        }
    }
}

thread_local! {
    /// Local state permission warnings recorded during the current command.
    ///
    /// The filesystem layer sits several calls below the command entry point
    /// and has no warning sink to thread through, so warnings are collected
    /// here and drained once the command finishes. This assumes local state I/O
    /// runs on the calling thread. Moving that I/O onto a worker thread would
    /// drop the warnings without any sign that it happened.
    static LOCAL_STATE_WARNINGS: RefCell<LocalStateWarningSink> =
        const { RefCell::new(LocalStateWarningSink::new()) };
}

/// Record one local state warning, ignoring a repeat of one already held.
///
/// A single command reads the active marker, the key documents, the trust
/// store and the configuration, so the same directory is inspected several
/// times over. The operator has one thing to repair and should be told once.
/// A repeat is never a loss, so only a new warning past the cap is counted.
pub(crate) fn record_local_state_warning(warning: LocalStateWarning) {
    LOCAL_STATE_WARNINGS.with(|sink| {
        let sink = &mut *sink.borrow_mut();
        if sink.warnings.len() < MAX_LOCAL_STATE_WARNINGS {
            push_unique_warning(&mut sink.warnings, warning);
            return;
        }
        if sink.warnings.contains(&warning) || sink.dropped.len() >= MAX_LOCAL_STATE_WARNINGS {
            return;
        }
        push_unique_warning(&mut sink.dropped, warning);
    });
}

/// Take the recorded warnings, leaving the sink empty.
///
/// The count the cap turned away travels beside the warnings rather than among
/// them, so a report that stops at the cap never passes for a complete one and
/// the caller never has to tell a finding from a note about the cap.
pub(crate) fn take_local_state_warnings() -> LocalStateWarningBatch {
    LOCAL_STATE_WARNINGS.with(|sink| {
        let sink = &mut *sink.borrow_mut();
        LocalStateWarningBatch {
            warnings: std::mem::take(&mut sink.warnings),
            dropped: std::mem::take(&mut sink.dropped).len(),
        }
    })
}

/// Drop the recorded warnings without reporting them.
///
/// Used by the diagnostic command, which returns the same violations as its
/// own findings and would otherwise report each one twice.
pub(crate) fn clear_local_state_warnings() {
    LOCAL_STATE_WARNINGS.with(|sink| *sink.borrow_mut() = LocalStateWarningSink::new());
}

/// Test-only guard that isolates the local state warning sink for one test.
/// Clears the sink on both ends so neighbouring tests cannot observe each other.
#[cfg(test)]
pub struct LocalStateWarningGuard;

#[cfg(test)]
impl LocalStateWarningGuard {
    pub fn new() -> Self {
        clear_local_state_warnings();
        Self
    }

    pub fn take(&self) -> LocalStateWarningBatch {
        take_local_state_warnings()
    }

    /// Take only the reasons, for a test that asserts on the wording alone.
    pub fn take_reasons(&self) -> Vec<String> {
        self.take()
            .warnings
            .into_iter()
            .map(|warning| warning.reason)
            .collect()
    }

    /// Take only the reasons for the warnings recorded under `root`.
    ///
    /// The directories above a temporary root belong to whoever built the
    /// machine, and one of them being group-writable is reported like any other
    /// finding. Restricting the take to the tree the caller built points the
    /// assertion at what that caller staged.
    pub fn take_reasons_under(&self, root: &Path) -> Vec<String> {
        self.take()
            .warnings
            .into_iter()
            .filter(|warning| warning.path.starts_with(root))
            .map(|warning| warning.reason)
            .collect()
    }

    /// Take the one reason recorded under `root`, for a test that stages a
    /// single violation and asserts on its wording.
    pub fn take_single_reason_under(&self, root: &Path) -> String {
        let reasons = self.take_reasons_under(root);
        assert_eq!(
            reasons.len(),
            1,
            "expected exactly one warning under {}, found {:?}",
            root.display(),
            reasons
        );
        reasons.into_iter().next().unwrap()
    }
}

#[cfg(test)]
impl Default for LocalStateWarningGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl Drop for LocalStateWarningGuard {
    fn drop(&mut self) {
        clear_local_state_warnings();
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_warning_test.rs"]
mod support_warning_test;
