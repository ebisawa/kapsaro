// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::format_output_notice_lines;
use std::path::PathBuf;

#[test]
fn test_format_output_notice_lines_keeps_long_output_path_inline() {
    let output_path = PathBuf::from(format!(
        "target/{}/secret.env.encrypted",
        "very-long-directory-name/".repeat(6)
    ));

    let lines = format_output_notice_lines("Encrypted to", &output_path);

    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("Encrypted to: "));
    assert!(lines[0].contains(output_path.to_string_lossy().as_ref()));
}
