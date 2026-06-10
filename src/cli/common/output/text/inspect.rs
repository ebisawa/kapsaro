// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for inspect commands.

use console::Style;

use crate::cli::common::output::text::layout;
use crate::cli::common::output::text::layout::LineTarget;
use kapsaro_core::cli_api::app::file::inspect::{InspectCommand, InspectOutput, InspectSection};

pub(crate) fn print_inspect_banner(input_display: &str) {
    layout::print_lines(
        format_inspect_banner_lines(input_display),
        LineTarget::Stderr,
    );
    eprintln!();
}

pub(crate) fn format_inspect_command_output(command: &InspectCommand) -> String {
    format_inspect_output(&command.output)
}

fn format_inspect_output(output: &InspectOutput) -> String {
    let title_style = Style::new().bold();
    let section_style = Style::new().bold();

    let mut out = String::new();
    for line in format_styled_value_lines("", &output.title, &title_style) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');
    for (index, section) in output.sections.iter().enumerate() {
        push_inspect_section(&mut out, section, &section_style);
        if index + 1 != output.sections.len() {
            out.push('\n');
        }
    }
    out.push('\n');
    out
}

fn push_inspect_section(out: &mut String, section: &InspectSection, section_style: &Style) {
    for line in format_styled_value_lines("", &section.title, section_style) {
        out.push_str(&line);
        out.push('\n');
    }
    for line in &section.lines {
        for rendered in format_inspect_line_lines(line) {
            out.push_str(&rendered);
            out.push('\n');
        }
    }
}

fn format_inspect_banner_lines(input_display: &str) -> Vec<String> {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    layout::format_value_lines("Inspecting: ", input_display)
        .into_iter()
        .map(|line| colorize_banner_line(&line, &dim, &bold))
        .collect()
}

fn colorize_banner_line(line: &str, dim: &Style, bold: &Style) -> String {
    if let Some(value) = line.strip_prefix("Inspecting: ") {
        return format!("{} {}", dim.apply_to("Inspecting:"), bold.apply_to(value));
    }
    bold.apply_to(line).to_string()
}

fn format_styled_value_lines(prefix: &str, value: &str, style: &Style) -> Vec<String> {
    layout::format_value_lines(prefix, value)
        .into_iter()
        .map(|line| style.apply_to(line).to_string())
        .collect()
}

fn format_inspect_line_lines(line: &str) -> Vec<String> {
    let (prefix, value) = split_inspect_line_prefix(line);
    layout::format_value_lines(prefix, value)
        .into_iter()
        .map(|line| colorize_inspect_line(&line))
        .collect()
}

fn split_inspect_line_prefix(line: &str) -> (&str, &str) {
    let Some(colon_index) = line.find(':') else {
        return split_leading_whitespace(line);
    };

    let value_start = line[colon_index + 1..]
        .find(|ch: char| !ch.is_whitespace())
        .map(|offset| colon_index + 1 + offset)
        .unwrap_or(line.len());
    line.split_at(value_start)
}

fn split_leading_whitespace(line: &str) -> (&str, &str) {
    let value_start = line
        .find(|ch: char| !ch.is_whitespace())
        .unwrap_or(line.len());
    line.split_at(value_start)
}

fn colorize_inspect_line(line: &str) -> String {
    let ok_style = Style::new().green().for_stdout();
    let ng_style = Style::new().red().for_stdout();
    let warning_style = Style::new().yellow().for_stdout();
    let is_disclosed_warning =
        line.contains("\u{26a0} DISCLOSED \u{2014} Secret may need rotation");
    if line.contains("\u{2714} OK") {
        line.replace(
            "\u{2714} OK",
            &format!("{}", ok_style.apply_to("\u{2714} OK")),
        )
    } else if line.contains("\u{2718} FAILED") {
        line.replace(
            "\u{2718} FAILED",
            &format!("{}", ng_style.apply_to("\u{2718} FAILED")),
        )
    } else if line.trim_start().starts_with("Warning:") || is_disclosed_warning {
        warning_style.apply_to(line).to_string()
    } else {
        line.to_string()
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_inspect_test.rs"]
mod tests;
