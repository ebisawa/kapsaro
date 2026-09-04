// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Top-level CLI error presentation.

use console::Style;
use kapsaro_core::Error;

use crate::cli::common::output::text::layout;

#[derive(Clone, Copy)]
enum ErrorLineStyle {
    Error,
    Detail,
}

struct ErrorDisplayLine {
    text: String,
    style: ErrorLineStyle,
}

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
    let lines = format_error_message_lines(error.format_user_message());
    format_stderr_error_lines(lines).join("\n")
}

fn format_error_message_lines(message: &str) -> Vec<ErrorDisplayLine> {
    let Some((summary, detail)) = message.split_once('\n') else {
        return format_error_lines(layout::format_diagnostic_lines("Error: ", message));
    };

    let mut lines = format_error_lines(layout::format_diagnostic_lines("Error: ", summary));
    let mut detail_lines = detail.split('\n').peekable();
    let mut continuation = Vec::new();

    while let Some(line) = detail_lines.peek().copied() {
        if is_error_detail_block_start(line) {
            break;
        }

        continuation.push(line.to_string());
        detail_lines.next();
    }

    if !continuation.is_empty() {
        lines.extend(format_error_lines(format_error_continuation_lines(
            &continuation.join("\n"),
        )));
    }

    lines.extend(format_detail_lines(detail_lines.map(str::to_string)));
    lines
}

fn format_error_continuation_lines(message: &str) -> Vec<String> {
    let continuation = " ".repeat(layout::visible_width("Error: "));
    message
        .split('\n')
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("{continuation}{line}")
            }
        })
        .collect()
}

fn is_error_detail_block_start(line: &str) -> bool {
    line.starts_with("Reason:") || line.starts_with("Options:")
}

fn format_error_lines(lines: Vec<String>) -> Vec<ErrorDisplayLine> {
    lines
        .into_iter()
        .map(|text| ErrorDisplayLine {
            text,
            style: ErrorLineStyle::Error,
        })
        .collect()
}

fn format_detail_lines(lines: impl IntoIterator<Item = String>) -> Vec<ErrorDisplayLine> {
    lines
        .into_iter()
        .map(|text| ErrorDisplayLine {
            text,
            style: ErrorLineStyle::Detail,
        })
        .collect()
}

fn format_stderr_error_lines(lines: Vec<ErrorDisplayLine>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| match line.style {
            ErrorLineStyle::Error => format_stderr_error_message(&line.text),
            ErrorLineStyle::Detail => line.text,
        })
        .collect()
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_error_test.rs"]
mod cli_error_test;
