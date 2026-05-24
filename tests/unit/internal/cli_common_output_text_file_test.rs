// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::format_output_notice_lines;
use crate::cli::common::output::text::layout::visible_width;
use std::path::PathBuf;

#[test]
fn test_format_output_notice_lines_wraps_long_output_path() {
    let output_path = PathBuf::from(format!(
        "target/{}/secret.env.encrypted",
        "very-long-directory-name/".repeat(6)
    ));

    let lines = format_output_notice_lines("Encrypted to", &output_path);

    assert!(lines.iter().all(|line| visible_width(line) <= 100));
    assert!(lines[0].starts_with("Encrypted to: "));
    assert!(lines
        .iter()
        .any(|line| line.contains("secret.env.encrypted")));
}
