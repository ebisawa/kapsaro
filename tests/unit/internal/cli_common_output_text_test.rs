// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use serial_test::serial;

use crate::cli::common::output::text::{format_truncation_notice, format_warning_line};
use crate::cli::stderr_color_guard::StderrColorGuard;

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
fn test_format_warning_line_keeps_long_warning_inline() {
    let _guard = StderrColorGuard::new(false);

    let rendered = format_warning_line(
        "Warning: Recipient kid is not active in this workspace. Run kapsaro rewrap before writing this artifact.",
    );

    assert_eq!(
        rendered,
        "Warning: Recipient kid is not active in this workspace. Run kapsaro rewrap before writing this artifact."
    );
}

/// A report the sink had to cut short says how much of it is missing, so the
/// operator repairs what is named and runs the command again for the rest.
#[test]
fn test_format_truncation_notice_names_the_findings_left_out() {
    let rendered = format_truncation_notice(6, 64);

    assert_eq!(
        rendered,
        "at least 6 further local state warnings were not reported because at most 64 are kept; \
         repair the entries named above and run the command again to see the rest"
    );
}

#[test]
#[serial]
fn test_format_warning_line_preserves_structured_details() {
    let _guard = StderrColorGuard::new(false);

    let rendered = format_warning_line(
        "Warning: Recipient kid is not active.\nKid: KAD1-AAAA\nAction: Run kapsaro rewrap.",
    );

    assert_eq!(
        rendered,
        concat!(
            "Warning: Recipient kid is not active.\n",
            "         Kid: KAD1-AAAA\n",
            "         Action: Run kapsaro rewrap."
        )
    );
}
