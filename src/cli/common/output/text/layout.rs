// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Terminal-width-aware text layout helpers for CLI renderers.
//! Keeps human-readable output bounded without changing JSON or wire data.

use console::strip_ansi_codes;

pub(crate) const TEXT_WIDTH: usize = 100;
const PAIR_SEPARATOR: &str = "  ";

pub(crate) fn capped_pair_left_width(left_width: usize, prefix: &str, right_width: usize) -> usize {
    let inline_width = TEXT_WIDTH
        .saturating_sub(visible_width(prefix))
        .saturating_sub(PAIR_SEPARATOR.len())
        .saturating_sub(right_width);
    left_width.min(inline_width)
}

pub(crate) fn format_pair_row(
    prefix: &str,
    left: &str,
    right: &str,
    left_width: usize,
) -> Vec<String> {
    let inline = format!("{prefix}{left:<left_width$}{PAIR_SEPARATOR}{right}");
    if visible_width(&inline) <= TEXT_WIDTH {
        return vec![inline];
    }

    let continuation = " ".repeat(visible_width(prefix) + PAIR_SEPARATOR.len());
    let mut lines = format_plain_line(prefix, left);
    lines.extend(format_plain_line(&continuation, right));
    lines
}

pub(crate) fn format_value_lines(prefix: &str, value: &str) -> Vec<String> {
    let continuation = " ".repeat(visible_width(prefix));
    format_value_lines_with_continuation(prefix, &continuation, value)
}

pub(crate) fn format_value_lines_with_continuation(
    prefix: &str,
    continuation: &str,
    value: &str,
) -> Vec<String> {
    wrap_value(prefix, continuation, value, TEXT_WIDTH)
}

fn format_plain_line(prefix: &str, value: &str) -> Vec<String> {
    format_value_lines(prefix, value)
}

fn wrap_value(prefix: &str, continuation: &str, value: &str, width: usize) -> Vec<String> {
    let mut chunks = split_value(value, available_width(prefix, width));
    if chunks.is_empty() {
        return vec![prefix.trim_end().to_string()];
    }

    let first = chunks.remove(0);
    let mut lines = vec![format!("{prefix}{first}")];
    let continuation_width = available_width(continuation, width);
    for chunk in chunks {
        for wrapped in split_value(&chunk, continuation_width) {
            lines.push(format!("{continuation}{wrapped}"));
        }
    }
    lines
}

fn split_value(value: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let width = width.max(1);

    for word in value.split_whitespace() {
        push_wrapped_word(&mut lines, &mut current, word, width);
    }

    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn push_wrapped_word(lines: &mut Vec<String>, current: &mut String, word: &str, width: usize) {
    for part in split_long_word(word, width) {
        let separator = usize::from(!current.is_empty());
        if visible_width(current) + separator + visible_width(&part) > width && !current.is_empty()
        {
            lines.push(std::mem::take(current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&part);
    }
}

fn split_long_word(word: &str, width: usize) -> Vec<String> {
    if visible_width(word) <= width {
        return vec![word.to_string()];
    }

    let mut parts = Vec::new();
    let mut current = String::new();
    for ch in word.chars() {
        if visible_width(&current) + 1 > width {
            parts.push(std::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn available_width(prefix: &str, width: usize) -> usize {
    width.saturating_sub(visible_width(prefix)).max(1)
}

pub(crate) fn visible_width(value: &str) -> usize {
    strip_ansi_codes(value).chars().count()
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_layout_test.rs"]
mod tests;
