// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text output helpers for CLI commands.

use console::Style;

pub(crate) mod doctor;
pub(crate) mod inspect;
pub(crate) mod key;
pub(crate) mod kv;
pub(crate) mod layout;
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
    format_warning_lines(message).join("\n")
}

pub(crate) fn print_warning_line(message: &str) {
    eprintln!("{}", format_warning_line(message));
}

pub(crate) fn print_warning(message: &str) {
    eprintln!("{}", format_warning_text(message));
}

pub(crate) fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        print_warning(warning);
    }
}

fn format_warning_text(message: &str) -> String {
    format_stderr_warning_lines(layout::format_diagnostic_lines("Warning: ", message)).join("\n")
}

fn format_warning_lines(message: &str) -> Vec<String> {
    let lines = match message.strip_prefix("Warning: ") {
        Some(body) => layout::format_diagnostic_lines("Warning: ", body),
        None => layout::format_value_lines("", message),
    };
    format_stderr_warning_lines(lines)
}

fn format_stderr_warning_lines(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| {
            Style::new()
                .yellow()
                .for_stderr()
                .apply_to(line)
                .to_string()
        })
        .collect()
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/cli_common_output_text_test.rs"]
mod tests;
