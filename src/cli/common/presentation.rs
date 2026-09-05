// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI-local path formatting and terminal capability helpers.
//! Keeps presentation policy that depends on the invocation out of the core API.

use std::path::{Path, PathBuf};

pub(crate) fn format_path_relative_to_cwd(path: &Path) -> String {
    DisplayBase::resolve().relative(path)
}

struct DisplayBase {
    cwd: Option<PathBuf>,
}

impl DisplayBase {
    fn resolve() -> Self {
        Self {
            cwd: std::env::current_dir().ok(),
        }
    }

    fn relative(&self, path: &Path) -> String {
        if let Some(cwd) = &self.cwd {
            if let Ok(relative) = path.strip_prefix(cwd) {
                return non_empty_display(relative);
            }
        }
        path.display().to_string()
    }
}

fn non_empty_display(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        ".".to_string()
    } else {
        path.display().to_string()
    }
}

pub(crate) mod tty {
    use std::io::IsTerminal;

    #[cfg(test)]
    use std::cell::Cell;

    #[cfg(test)]
    thread_local! {
        static INTERACTIVE_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    }

    /// Report whether an operator can answer a prompt on this invocation.
    ///
    /// A terminal on stdin is the one signal every prompt in the CLI reads;
    /// no environment variable can widen or narrow it.
    pub(crate) fn is_interactive() -> bool {
        #[cfg(test)]
        if let Some(value) = INTERACTIVE_OVERRIDE.with(Cell::get) {
            return value;
        }
        std::io::stdin().is_terminal()
    }

    #[cfg(test)]
    pub(crate) fn set_interactive_override(value: Option<bool>) {
        INTERACTIVE_OVERRIDE.with(|cell| cell.set(value));
    }
}
