// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text layout helpers for CLI renderers.
//! Preserves explicit line breaks without applying terminal-width wrapping.

use console::strip_ansi_codes;

const PAIR_SEPARATOR: &str = "  ";

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

pub(crate) fn visible_width(value: &str) -> usize {
    strip_ansi_codes(value).chars().count()
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_layout_test.rs"]
mod tests;
