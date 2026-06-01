// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Top-level CLI error presentation.

use console::Style;
use kapsaro_core::Error;

use crate::cli::common::output::text::layout;

pub(crate) fn print_error(error: &Error) {
    eprintln!("{}", format_error_line(error));
}

pub(crate) fn print_clap_error(error: &clap::Error) -> i32 {
    if error.use_stderr() {
        eprint!("{}", format_stderr_error_message(&error.to_string()));
    } else {
        print!("{error}");
    }
    error.exit_code()
}

pub(crate) fn format_stderr_error_message(message: &str) -> String {
    Style::new()
        .red()
        .for_stderr()
        .apply_to(message)
        .to_string()
}

fn format_error_line(error: &Error) -> String {
    let lines = layout::format_diagnostic_lines("Error: ", error.format_user_message());
    format_stderr_error_lines(lines).join("\n")
}

fn format_stderr_error_lines(lines: Vec<String>) -> Vec<String> {
    let mut lines = lines.into_iter();
    let Some(first_line) = lines.next() else {
        return Vec::new();
    };

    let mut formatted = vec![format_stderr_error_message(&first_line)];
    formatted.extend(lines);
    formatted
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_error_test.rs"]
mod tests;
