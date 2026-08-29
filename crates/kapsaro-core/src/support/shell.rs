// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Repair commands an operator can paste into a shell.
//! Quotes a path as one word so a name chosen by someone else cannot extend it.

use crate::support::display::needs_placeholder;
use std::path::{Path, PathBuf};

/// One path quoted as a single POSIX shell word.
///
/// Returns `None` when the path holds bytes that are not valid UTF-8, or a
/// character that does not stand for itself on a terminal. No portable shell
/// word reproduces invalid UTF-8, and a lossy rendering would name a path that
/// does not exist. Such a character stays syntactically valid inside single
/// quotes, but this string is later embedded in a warning message and printed
/// beside an escaped path: a newline could forge a second line on standard
/// error, and a bidirectional override could reorder the command so it appears
/// to repair a different path than the one it names. No command is better than
/// one that can be abused that way.
pub(crate) fn quote_posix_argument(path: &Path) -> Option<String> {
    let raw = path.to_str()?;
    if raw.chars().any(needs_placeholder) {
        return None;
    }
    let mut quoted = String::with_capacity(raw.len() + 2);
    quoted.push('\'');
    for ch in raw.chars() {
        // A single quote cannot appear inside single quotes. Leaving the
        // quoted word, spelling the character, and entering it again is the
        // portable way through, and it keeps everything one word.
        if ch == '\'' {
            quoted.push_str(r"'\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    Some(quoted)
}

/// A repair command naming `path`, absolute so it runs from anywhere.
///
/// `--` separates the path from the options: quoting keeps a name one word but
/// does nothing about a leading `-`, which the command would still read as an
/// option of its own. Returns `None` when the path cannot be made absolute or
/// cannot be quoted safely, rather than showing a command that would act on a
/// different file once pasted into another working directory.
pub(crate) fn format_repair_command(command: &str, path: &Path) -> Option<String> {
    let absolute = absolute_command_path(path)?;
    let argument = quote_posix_argument(&absolute)?;
    Some(format!("{command} -- {argument}"))
}

/// Add the repair to an explanation, saying so when none can be shown.
pub(crate) fn append_repair_command(explanation: &str, command: &str, path: &Path) -> String {
    match format_repair_command(command, path) {
        Some(repair) => format!("{explanation}; run: {repair}"),
        None => format!(
            "{explanation}; no repair command is shown because the path holds bytes that are not \
             valid UTF-8 or contains characters that cannot be displayed safely"
        ),
    }
}

/// The path a pasted command has to name.
///
/// Lexical only: `std::path::absolute` neither touches the filesystem nor
/// resolves links, so the entry a finding inspected stays the entry its repair
/// names. Returns `None` when the path cannot be made absolute: a relative
/// fallback would run against whatever directory the command is pasted into,
/// acting on a different file than the one a finding inspected.
fn absolute_command_path(path: &Path) -> Option<PathBuf> {
    std::path::absolute(path).ok()
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_shell_test.rs"]
mod support_shell_test;
