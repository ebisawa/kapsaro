// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text output helpers for CLI commands.

use console::Style;
use kapsaro_core::api::diagnostics::{DiagnosticBatch, DiagnosticCompleteness};

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

/// Print every local state finding, then say what the batch left out.
pub(crate) fn print_local_state_diagnostics(batch: &DiagnosticBatch) {
    for diagnostic in batch.diagnostics() {
        print_warning(diagnostic.reason());
    }
    if let DiagnosticCompleteness::Truncated(truncation) = batch.completeness() {
        print_warning(&format_truncation_notice(
            truncation.dropped_at_least(),
            truncation.retained_limit(),
        ));
    }
}

/// Name how much of the finding the batch could not carry.
///
/// A report that stops at the retention limit would otherwise read as the whole
/// of it, so the operator is told to repair what is named and run again.
fn format_truncation_notice(dropped_at_least: usize, retained_limit: usize) -> String {
    format!(
        "at least {dropped_at_least} further local state warnings were not reported because at \
         most {retained_limit} are kept; repair the entries named above and run the command again \
         to see the rest"
    )
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
