// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use console::{colors_enabled, set_colors_enabled};
use serial_test::serial;

use super::{colorize_inspect_line, format_inspect_banner_lines, format_inspect_output};
use secretenv_core::cli_api::app::file::inspect::{InspectOutput, InspectSection};

struct StdoutColorGuard {
    enabled: bool,
}

impl StdoutColorGuard {
    fn new(enabled: bool) -> Self {
        let previous = colors_enabled();
        set_colors_enabled(enabled);
        Self { enabled: previous }
    }
}

impl Drop for StdoutColorGuard {
    fn drop(&mut self) {
        set_colors_enabled(self.enabled);
    }
}

#[test]
#[serial]
fn test_colorize_inspect_line_keeps_warning_plain_when_stdout_colors_disabled() {
    let _guard = StdoutColorGuard::new(false);

    let rendered = colorize_inspect_line(
        "  Warning:     \u{26a0} PublicKey for 'ebisawa' has expired (expires_at: 2026-04-10T12:08:05Z)",
    );

    assert_eq!(
        rendered,
        "  Warning:     \u{26a0} PublicKey for 'ebisawa' has expired (expires_at: 2026-04-10T12:08:05Z)"
    );
}

#[test]
#[serial]
fn test_colorize_inspect_line_keeps_ok_status_colored_when_stdout_colors_enabled() {
    let _guard = StdoutColorGuard::new(true);

    let rendered = colorize_inspect_line("  Status:      \u{2714} OK");

    assert!(rendered.contains("\u{1b}[32m\u{2714} OK\u{1b}[0m"));
}

#[test]
#[serial]
fn test_format_inspect_output_keeps_long_section_lines_inline() {
    let _guard = StdoutColorGuard::new(false);
    let output = InspectOutput {
        title: "File Encryption".to_string(),
        sections: vec![InspectSection {
            title: "Verification".to_string(),
            lines: vec![format!(
                "  Warning:     PublicKey for '{}' has expired and needs rotation before reuse",
                "release.engineering.".repeat(6)
            )],
        }],
    };

    let rendered = format_inspect_output(&output);

    assert!(rendered.contains("  Warning:     PublicKey"));
    assert!(rendered.contains("release.engineering."));
}

#[test]
#[serial]
fn test_format_inspect_banner_lines_keeps_long_input_display_inline() {
    let _guard = StdoutColorGuard::new(false);
    let input_display = format!(
        "target/{}/secret.env.encrypted",
        "very-long-directory-name/".repeat(6)
    );

    let lines = format_inspect_banner_lines(&input_display);

    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("Inspecting: "));
    assert!(lines[0].contains(&input_display));
}

#[test]
#[serial]
fn test_format_inspect_output_keeps_long_title_and_section_title_inline() {
    let _guard = StdoutColorGuard::new(false);
    let output = InspectOutput {
        title: format!("File Encryption {}", "release engineering ".repeat(8)),
        sections: vec![InspectSection {
            title: format!("Signature Verification {}", "long section title ".repeat(8)),
            lines: vec!["  Status:      \u{2714} OK".to_string()],
        }],
    };

    let rendered = format_inspect_output(&output);

    assert!(rendered.contains("File Encryption"));
    assert!(rendered.contains("Signature Verification"));
    assert!(rendered.contains("release engineering"));
    assert!(rendered.contains("long section title"));
}
