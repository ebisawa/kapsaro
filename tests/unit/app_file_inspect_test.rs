// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use console::{colors_enabled, set_colors_enabled};
use serial_test::serial;

use super::colorize_inspect_line;

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
fn test_colorize_inspect_line_adds_warning_color_when_stdout_colors_enabled() {
    let _guard = StdoutColorGuard::new(true);

    let rendered = colorize_inspect_line(
        "  Warning:     \u{26a0} PublicKey for 'ebisawa' has expired (expires_at: 2026-04-10T12:08:05Z)",
    );

    assert!(rendered.starts_with("\u{1b}[33m  Warning:     \u{26a0} PublicKey for 'ebisawa'"));
    assert!(rendered.ends_with("\u{1b}[0m"));
}

#[test]
#[serial]
fn test_colorize_inspect_line_adds_disclosed_color_when_stdout_colors_enabled() {
    let _guard = StdoutColorGuard::new(true);

    let rendered =
        colorize_inspect_line("      \u{26a0} DISCLOSED \u{2014} Secret may need rotation");

    assert!(rendered
        .starts_with("\u{1b}[33m      \u{26a0} DISCLOSED \u{2014} Secret may need rotation"));
    assert!(rendered.ends_with("\u{1b}[0m"));
}

#[test]
#[serial]
fn test_colorize_inspect_line_keeps_ok_status_colored_when_stdout_colors_enabled() {
    let _guard = StdoutColorGuard::new(true);

    let rendered = colorize_inspect_line("  Status:      \u{2714} OK");

    assert!(rendered.contains("\u{1b}[32m\u{2714} OK\u{1b}[0m"));
}
