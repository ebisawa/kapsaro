// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use console::{colors_enabled_stderr, set_colors_enabled_stderr};
use serial_test::serial;

use crate::cli::common::output::text::build_warning_line;

struct StderrColorGuard {
    enabled: bool,
}

impl StderrColorGuard {
    fn new(enabled: bool) -> Self {
        let previous = colors_enabled_stderr();
        set_colors_enabled_stderr(enabled);
        Self { enabled: previous }
    }
}

impl Drop for StderrColorGuard {
    fn drop(&mut self) {
        set_colors_enabled_stderr(self.enabled);
    }
}

#[test]
#[serial]
fn test_build_warning_line_keeps_plain_text_when_stderr_colors_disabled() {
    let _guard = StderrColorGuard::new(false);

    let rendered = build_warning_line("Warning: test message");

    assert_eq!(rendered, "Warning: test message");
}

#[test]
#[serial]
fn test_build_warning_line_adds_ansi_color_when_stderr_colors_enabled() {
    let _guard = StderrColorGuard::new(true);

    let rendered = build_warning_line("Warning: test message");

    assert!(rendered.starts_with("\u{1b}[33mWarning: test message"));
    assert!(rendered.ends_with("\u{1b}[0m"));
}
