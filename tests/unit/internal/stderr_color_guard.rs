// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! RAII guard that pins the stderr color state of the console crate
//! so tests asserting styled output stay deterministic across TTY environments.

use console::{colors_enabled_stderr, set_colors_enabled_stderr};

pub(crate) struct StderrColorGuard {
    previous: bool,
}

impl StderrColorGuard {
    pub(crate) fn new(enabled: bool) -> Self {
        let previous = colors_enabled_stderr();
        set_colors_enabled_stderr(enabled);
        Self { previous }
    }
}

impl Drop for StderrColorGuard {
    fn drop(&mut self) {
        set_colors_enabled_stderr(self.previous);
    }
}
