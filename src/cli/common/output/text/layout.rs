// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text layout helpers for CLI renderers.
//! Preserves explicit line breaks without applying terminal-width wrapping.

use console::strip_ansi_codes;
use kapsaro_core::cli_api::presentation::kid::{format_kid_display, format_kid_display_lossy};

const PAIR_SEPARATOR: &str = "  ";

pub(crate) enum LabelAlignment {
    ColonAfterLabel,
    ColonAfterWidth,
}

pub(crate) enum LineTarget {
    Stdout,
    Stderr,
}

pub(crate) enum KidDisplayFallback {
    Raw,
    Sanitized,
}

pub(crate) fn format_pair_row(
    prefix: &str,
    left: &str,
    right: &str,
    left_width: usize,
) -> Vec<String> {
    vec![format!(
        "{prefix}{left:<left_width$}{PAIR_SEPARATOR}{right}"
    )]
}

pub(crate) fn format_labeled_value_lines(
    label: &str,
    value: &str,
    label_width: usize,
    alignment: LabelAlignment,
) -> Vec<String> {
    let prefix = match alignment {
        LabelAlignment::ColonAfterLabel => {
            let padding = label_width.saturating_sub(label.len()) + 1;
            format!("  {label}:{:padding$}", "")
        }
        LabelAlignment::ColonAfterWidth => format!("  {label:<label_width$}: "),
    };
    format_value_lines(&prefix, value)
}

pub(crate) fn format_value_lines(prefix: &str, value: &str) -> Vec<String> {
    format_prefixed_lines(prefix, prefix, value)
}

pub(crate) fn format_diagnostic_lines(prefix: &str, message: &str) -> Vec<String> {
    let continuation = " ".repeat(visible_width(prefix));
    format_prefixed_lines(prefix, &continuation, message)
}

fn format_prefixed_lines(first_prefix: &str, continuation: &str, value: &str) -> Vec<String> {
    if value.is_empty() {
        return vec![first_prefix.trim_end().to_string()];
    }

    value
        .split('\n')
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                format!("{first_prefix}{line}")
            } else if line.is_empty() {
                String::new()
            } else {
                format!("{continuation}{line}")
            }
        })
        .collect()
}

pub(crate) fn push_section(lines: &mut Vec<String>, title: String, body: Vec<String>) {
    lines.push(String::new());
    lines.push(title);
    lines.extend(body);
}

pub(crate) fn print_lines(lines: impl IntoIterator<Item = String>, target: LineTarget) {
    for line in lines {
        match target {
            LineTarget::Stdout => println!("{line}"),
            LineTarget::Stderr => eprintln!("{line}"),
        }
    }
}

pub(crate) fn format_kid_display_text(kid: &str, fallback: KidDisplayFallback) -> String {
    match fallback {
        KidDisplayFallback::Raw => format_kid_display(kid).unwrap_or_else(|_| kid.to_string()),
        KidDisplayFallback::Sanitized => format_kid_display_lossy(kid),
    }
}

pub(crate) fn visible_width(value: &str) -> usize {
    strip_ansi_codes(value).chars().count()
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_layout_test.rs"]
mod tests;
