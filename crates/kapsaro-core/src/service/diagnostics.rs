// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Non-fatal diagnostics collected while local state is read or created.
//! Lets an embedding application surface what the operator should look at.

use std::path::{Path, PathBuf};

use crate::error::LOCAL_STATE_PERMISSIONS_RULE;
use crate::support::warning::{
    self, LocalStateWarning, LocalStateWarningCode, MAX_LOCAL_STATE_WARNINGS,
};

/// Stable code one diagnostic belongs to.
///
/// The code is what a caller branches on, so it is a type rather than the rule
/// string. [`DiagnosticCode::as_str`] gives the same spelling the diagnostic
/// command reports for the matching finding.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticCode {
    /// A local state entry, or a directory leading to it, that another user can
    /// reach.
    LocalStatePermissions,
}

impl DiagnosticCode {
    /// The stable rule string for this code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalStatePermissions => LOCAL_STATE_PERMISSIONS_RULE,
        }
    }
}

/// One local state finding: its code, the entry it is about, and why.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocalStateDiagnostic {
    code: DiagnosticCode,
    path: PathBuf,
    reason: String,
}

impl LocalStateDiagnostic {
    /// The code this finding belongs to.
    pub fn code(&self) -> DiagnosticCode {
        self.code
    }

    /// The entry the operator has to look at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// One sentence naming what is wrong and how to repair it.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl From<LocalStateWarning> for LocalStateDiagnostic {
    fn from(warning: LocalStateWarning) -> Self {
        Self {
            code: match warning.code() {
                LocalStateWarningCode::Permissions => DiagnosticCode::LocalStatePermissions,
            },
            path: warning.path().to_path_buf(),
            reason: warning.reason().to_string(),
        }
    }
}

impl From<LocalStateDiagnostic> for LocalStateWarning {
    fn from(diagnostic: LocalStateDiagnostic) -> Self {
        Self::new(
            match diagnostic.code {
                DiagnosticCode::LocalStatePermissions => LocalStateWarningCode::Permissions,
            },
            &diagnostic.path,
            diagnostic.reason,
        )
    }
}

/// How much of the finding one batch could not carry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DiagnosticTruncation {
    dropped_at_least: usize,
    retained_limit: usize,
}

impl DiagnosticTruncation {
    /// Lower bound on the distinct diagnostics that were not held.
    ///
    /// The count of turned-away diagnostics is capped as well, so a caller that
    /// never drains sees a floor on what is missing rather than an exact total.
    pub fn dropped_at_least(self) -> usize {
        self.dropped_at_least
    }

    /// How many diagnostics one batch holds at most.
    pub fn retained_limit(self) -> usize {
        self.retained_limit
    }
}

/// Whether a batch carries every diagnostic recorded since the last take.
///
/// A capped report has to be told apart from a complete one, so this is a
/// verdict the caller matches on rather than an entry among the diagnostics.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DiagnosticCompleteness {
    Complete,
    Truncated(DiagnosticTruncation),
}

/// The diagnostics one take carries, and whether they are all of them.
#[derive(Debug, Clone)]
pub struct DiagnosticBatch {
    diagnostics: Vec<LocalStateDiagnostic>,
    completeness: DiagnosticCompleteness,
}

impl DiagnosticBatch {
    /// The findings this take carried, in the order they were recorded.
    pub fn diagnostics(&self) -> &[LocalStateDiagnostic] {
        &self.diagnostics
    }

    /// Whether the findings are the whole of what was recorded.
    pub fn completeness(&self) -> DiagnosticCompleteness {
        self.completeness
    }

    /// Take ownership of the findings, dropping the completeness verdict.
    pub fn into_diagnostics(self) -> Vec<LocalStateDiagnostic> {
        self.diagnostics
    }

    /// Convert the public diagnostic form back into the command sink form.
    pub(crate) fn into_warning_batch(self) -> warning::LocalStateWarningBatch {
        let dropped = match self.completeness {
            DiagnosticCompleteness::Complete => 0,
            DiagnosticCompleteness::Truncated(truncation) => truncation.dropped_at_least,
        };
        warning::LocalStateWarningBatch {
            warnings: self
                .diagnostics
                .into_iter()
                .map(LocalStateWarning::from)
                .collect(),
            dropped,
        }
    }
}

/// Return service-owned diagnostics to the first-party command warning sink.
pub(crate) fn restore_local_state_warnings(batch: DiagnosticBatch) {
    warning::restore_local_state_warnings(batch.into_warning_batch());
}

/// Take the local state permission warnings recorded so far.
///
/// Local state permissions belong to the operator and the machine's
/// administrator, so an entry that others can reach is reported rather than
/// refused. The findings are deduplicated, and this call empties the buffer.
///
/// The buffer is bound to the calling thread. Warnings recorded while local
/// state was read on one thread can only be taken on that same thread, and a
/// call from anywhere else returns an empty batch without saying that anything
/// was missed — an empty result and "there were no warnings" look identical
/// from here. An application that performs local state I/O on a worker thread
/// has to take the warnings on that worker.
///
/// Taking once per operation is what keeps the report complete, not merely
/// tidy. A bounded number of warnings is held, and the count of distinct
/// warnings turned away is itself capped; once both are full, a further new
/// warning is not even counted, so a caller that never drains loses the most
/// recent findings rather than the oldest.
pub fn take_local_state_warnings() -> DiagnosticBatch {
    from_warning_batch(warning::take_local_state_warnings())
}

pub(crate) fn from_warning_batch(batch: warning::LocalStateWarningBatch) -> DiagnosticBatch {
    DiagnosticBatch {
        diagnostics: batch
            .warnings
            .into_iter()
            .map(LocalStateDiagnostic::from)
            .collect(),
        completeness: evaluate_completeness(batch.dropped),
    }
}

fn evaluate_completeness(dropped: usize) -> DiagnosticCompleteness {
    if dropped == 0 {
        return DiagnosticCompleteness::Complete;
    }
    DiagnosticCompleteness::Truncated(DiagnosticTruncation {
        dropped_at_least: dropped,
        retained_limit: MAX_LOCAL_STATE_WARNINGS,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/internal/service_diagnostics_test.rs"]
mod service_diagnostics_test;
