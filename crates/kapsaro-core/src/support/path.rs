// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Path rendering for messages an operator reads, and the path shapes they share.
//! Shortens a path against the working directory, spells out control characters, and names the
//! directory an empty path stands for.

use crate::support::display::format_path_for_message;
use std::path::{Path, PathBuf};

/// Display a path relative to the current working directory when possible.
///
/// If `strip_prefix(cwd)` fails, falls back to the original `path.display()`.
/// The working directory itself strips to nothing, which would render as an
/// empty string and name no path at all, so it is spelled as the current
/// directory instead.
pub fn format_path_relative_to_cwd(path: &Path) -> String {
    DisplayBase::resolve().relative(path)
}

/// Name a path inside a finding the operator has to act on.
///
/// The working directory is the reader's own frame, so a path below it is
/// shortest to recognise there. A path that *is* the working directory has no
/// short form worth printing: `.` names the entry only to whoever is standing
/// in it, and a finding is read and repaired elsewhere. Control characters are
/// spelled out because an entry name is chosen by whoever can write the
/// directory, and a newline in one would forge a second report line.
pub(crate) fn format_finding_path(path: &Path) -> String {
    DisplayBase::resolve().finding(path)
}

/// The working directory a run of findings is rendered against.
///
/// Reading the working directory is a system call, and a walk over a whole tree
/// renders a path for every entry it reports. Resolving it once when the walk
/// starts pays for it once, and it also keeps every finding of one walk phrased
/// against the same directory, which a per-finding read cannot promise while
/// another thread is free to move it.
pub(crate) struct DisplayBase {
    cwd: Option<PathBuf>,
}

impl DisplayBase {
    /// Read the working directory once, for the findings that follow.
    pub(crate) fn resolve() -> Self {
        Self {
            cwd: std::env::current_dir().ok(),
        }
    }

    /// Shorten a path against the directory this base resolved.
    fn relative(&self, path: &Path) -> String {
        if let Some(cwd) = &self.cwd {
            if let Ok(relative) = path.strip_prefix(cwd) {
                return non_empty_display(relative);
            }
        }
        path.display().to_string()
    }

    /// Name a path inside a finding, spelling out what a terminal would act on.
    pub(crate) fn finding(&self, path: &Path) -> String {
        let relative = self.relative(path);
        let named = if relative == "." {
            path.display().to_string()
        } else {
            relative
        };
        format_path_for_message(&named)
    }
}

fn non_empty_display(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        return ".".to_string();
    }
    path.display().to_string()
}

/// Name the current directory where an empty path would otherwise stand.
///
/// `Path::parent` answers with an empty path once a relative chain runs out of
/// components, and an empty path names nothing a system call accepts, so the
/// directory it stands for is spelled out instead.
pub(crate) fn path_or_current_dir(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_path_test.rs"]
mod support_path_test;
