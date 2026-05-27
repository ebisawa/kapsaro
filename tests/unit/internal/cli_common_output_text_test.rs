// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use console::{colors_enabled_stderr, set_colors_enabled_stderr};
use serial_test::serial;

use crate::cli::common::output::text::format_warning_line;
use crate::cli::common::output::text::layout::{visible_width, TEXT_WIDTH};

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
fn test_format_warning_line_keeps_plain_text_when_stderr_colors_disabled() {
    let _guard = StderrColorGuard::new(false);

    let rendered = format_warning_line("Warning: test message");

    assert_eq!(rendered, "Warning: test message");
}

#[test]
#[serial]
fn test_format_warning_line_adds_ansi_color_when_stderr_colors_enabled() {
    let _guard = StderrColorGuard::new(true);

    let rendered = format_warning_line("Warning: test message");

    assert!(rendered.starts_with("\u{1b}[33mWarning: test message"));
    assert!(rendered.ends_with("\u{1b}[0m"));
}

#[test]
#[serial]
fn test_format_warning_line_wraps_long_warning_to_80_columns() {
    let _guard = StderrColorGuard::new(false);

    let rendered = format_warning_line(
        "Warning: Recipient kid is not active in this workspace. Run secretenv rewrap before writing this artifact.",
    );

    assert_eq!(
        rendered,
        concat!(
            "Warning: Recipient kid is not active in this workspace. Run secretenv rewrap\n",
            "         before writing this artifact."
        )
    );
    assert!(rendered
        .lines()
        .all(|line| visible_width(line) <= TEXT_WIDTH));
}

#[test]
#[serial]
fn test_format_warning_line_preserves_structured_details() {
    let _guard = StderrColorGuard::new(false);

    let rendered = format_warning_line(
        "Warning: Recipient kid is not active.\nKid: KAD1-AAAA\nAction: Run secretenv rewrap.",
    );

    assert_eq!(
        rendered,
        concat!(
            "Warning: Recipient kid is not active.\n",
            "         Kid: KAD1-AAAA\n",
            "         Action: Run secretenv rewrap."
        )
    );
}
