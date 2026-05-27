// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use console::{colors_enabled_stderr, set_colors_enabled_stderr};
use secretenv_core::Error;
use serial_test::serial;

use super::format_error_line;

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
fn test_format_error_line_keeps_plain_text_when_stderr_colors_disabled() {
    let _guard = StderrColorGuard::new(false);
    let error = Error::build_invalid_argument_error("broken input");

    let rendered = format_error_line(&error);

    assert_eq!(rendered, "Error: broken input");
}

#[test]
#[serial]
fn test_format_error_line_adds_ansi_color_when_stderr_colors_enabled() {
    let _guard = StderrColorGuard::new(true);
    let error = Error::build_invalid_argument_error("broken input");

    let rendered = format_error_line(&error);

    assert!(rendered.starts_with("\u{1b}[31mError: broken input"));
    assert!(rendered.ends_with("\u{1b}[0m"));
}
