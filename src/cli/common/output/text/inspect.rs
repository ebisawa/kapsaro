// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for inspect commands.

use console::Style;

pub(crate) fn print_inspect_banner(input_display: &str) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    eprintln!(
        "{} {}\n",
        dim.apply_to("Inspecting:"),
        bold.apply_to(input_display)
    );
}
