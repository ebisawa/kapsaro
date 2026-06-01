// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{format_created_workspace_summary_lines, format_init_noop_summary_lines};
use std::path::PathBuf;

#[test]
fn test_format_created_workspace_summary_lines_keeps_long_workspace_path_inline() {
    let workspace_path = long_workspace_path();

    let lines = format_created_workspace_summary_lines(&workspace_path);

    assert!(lines[0].starts_with("Creating workspace "));
    assert!(lines[0].contains(workspace_path.to_string_lossy().as_ref()));
}

#[test]
fn test_format_init_noop_summary_lines_keeps_long_workspace_path_inline() {
    let workspace_path = long_workspace_path();

    let lines = format_init_noop_summary_lines(&workspace_path);

    assert!(lines[0].starts_with("Workspace already initialized at "));
    assert!(lines[0].contains(workspace_path.to_string_lossy().as_ref()));
    assert!(lines
        .iter()
        .any(|line| line.contains("only bootstraps a new workspace")));
}

fn long_workspace_path() -> PathBuf {
    PathBuf::from(format!(
        "target/{}/.kapsaro",
        "very-long-workspace-directory-name/".repeat(6)
    ))
}
