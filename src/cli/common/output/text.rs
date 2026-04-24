// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text output helpers for CLI commands.

use console::Style;

pub(crate) mod inspect;
pub(crate) mod key;
pub(crate) mod kv;
pub(crate) mod member;
pub(crate) mod registration;
pub(crate) mod rewrap;
pub(crate) mod trust;

pub(crate) fn print_optional_status(message: Option<&str>, quiet: bool) {
    if quiet {
        return;
    }
    if let Some(message) = message {
        eprintln!("{}", message);
    }
}

pub(crate) fn format_warning_line(message: &str) -> String {
    Style::new()
        .yellow()
        .for_stderr()
        .apply_to(message)
        .to_string()
}

pub(crate) fn print_warning_line(message: &str) {
    eprintln!("{}", format_warning_line(message));
}

pub(crate) fn print_warning(message: &str) {
    print_warning_line(&format!("Warning: {}", message));
}

pub(crate) fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        print_warning(warning);
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/cli_common_output_text_test.rs"]
mod tests;
