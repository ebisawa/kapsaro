// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Wording for a change that landed and then hit a problem of its own.
//! Keeps a completed change from being reported as one that never happened.

use crate::support::path::format_finding_path;
use std::path::Path;

/// The change that finished before the trouble started.
///
/// A removal reported as a write sends the operator looking for a file that is
/// no longer there, which is the same confusion in the other direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompletedChange {
    Written,
    Removed,
}

impl CompletedChange {
    fn phrase(self) -> &'static str {
        match self {
            Self::Written => "was written",
            Self::Removed => "was removed",
        }
    }
}

/// Say that `subject` reached `path` before `condition` went wrong.
///
/// What the operator does next depends on knowing the change is on disk. A bare
/// failure reads as "nothing happened", which invites a retry that is either
/// pointless or, for a key pair, refused because the entry is already there.
pub(crate) fn format_post_change_failure(
    subject: &str,
    path: &Path,
    change: CompletedChange,
    condition: &str,
    detail: &str,
) -> String {
    format!(
        "{subject} {} {}, but {condition}: {detail}",
        format_finding_path(path),
        change.phrase()
    )
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_post_write_test.rs"]
mod support_post_write_test;
