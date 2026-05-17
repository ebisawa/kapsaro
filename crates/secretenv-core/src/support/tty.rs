// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! TTY detection for interactive/non-interactive mode.

use std::cell::Cell;
use std::io::IsTerminal;

thread_local! {
    static INTERACTIVE_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Returns true if stdin is a TTY (interactive session).
///
/// Non-interactive is defined as stdin not being a TTY.
/// An override may be set via [`set_interactive_override`] for testing.
pub fn is_interactive() -> bool {
    INTERACTIVE_OVERRIDE.with(|cell| cell.get().unwrap_or_else(|| std::io::stdin().is_terminal()))
}

/// Override the result of [`is_interactive`] on the current thread.
///
/// Pass `Some(false)` to force non-interactive mode, or `None` to
/// restore the default stdin-based detection.
pub fn set_interactive_override(value: Option<bool>) {
    INTERACTIVE_OVERRIDE.with(|cell| cell.set(value));
}
