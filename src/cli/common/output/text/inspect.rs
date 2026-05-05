// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for inspect commands.

use console::Style;

use crate::app::file::inspect::InspectCommand;
use crate::feature::inspect::{InspectOutput, InspectSection};

pub(crate) fn print_inspect_banner(input_display: &str) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    eprintln!(
        "{} {}\n",
        dim.apply_to("Inspecting:"),
        bold.apply_to(input_display)
    );
}

pub(crate) fn format_inspect_command_output(command: &InspectCommand) -> String {
    format_inspect_output(&command.output)
}

fn format_inspect_output(output: &InspectOutput) -> String {
    let title_style = Style::new().bold();
    let section_style = Style::new().bold();

    let mut out = String::new();
    out.push_str(&format!("{}\n", title_style.apply_to(&output.title)));
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
    out.push_str(&format!("{}\n", section_style.apply_to(&section.title)));
    for line in &section.lines {
        out.push_str(&colorize_inspect_line(line));
        out.push('\n');
    }
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
