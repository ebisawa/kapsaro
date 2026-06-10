// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for registration commands.

use std::path::Path;

use crate::cli::common::output::text::layout;
use crate::cli::common::output::text::layout::LineTarget;
use kapsaro_core::cli_api::app::registration::types::RegistrationMode;
use kapsaro_core::cli_api::presentation::path::format_path_relative_to_cwd;

pub(crate) fn print_created_workspace_summary(workspace_path: &Path) {
    layout::print_lines(
        format_created_workspace_summary_lines(workspace_path),
        LineTarget::Stderr,
    );
    eprintln!("  Created members/active/");
    eprintln!("  Created members/incoming/");
    eprintln!("  Created secrets/");
}

pub(crate) fn print_init_noop_summary(workspace_path: &Path) {
    layout::print_lines(
        format_init_noop_summary_lines(workspace_path),
        LineTarget::Stderr,
    );
}

pub(crate) fn print_registration_next_steps(mode: RegistrationMode, is_new_workspace: bool) {
    match mode {
        RegistrationMode::Init if is_new_workspace => {
            eprintln!("Ready! Commit .kapsaro/ to your repository.");
        }
        RegistrationMode::Init | RegistrationMode::Join => {
            eprintln!("Ready! Create a PR to share your public key with the team.");
        }
    }
}

fn format_workspace_display(path: &Path) -> String {
    format!("{}/", format_path_relative_to_cwd(path))
}

fn format_created_workspace_summary_lines(workspace_path: &Path) -> Vec<String> {
    layout::format_value_lines(
        "Creating workspace ",
        &format_workspace_display(workspace_path),
    )
}

fn format_init_noop_summary_lines(workspace_path: &Path) -> Vec<String> {
    let mut lines = layout::format_value_lines(
        "Workspace already initialized at ",
        &format_workspace_display(workspace_path),
    );
    lines.extend(layout::format_value_lines(
        "",
        "`kapsaro init` only bootstraps a new workspace and first member.",
    ));
    lines.extend(layout::format_value_lines(
        "",
        "Use `kapsaro join` to submit a key to an existing workspace.",
    ));
    lines
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_registration_test.rs"]
mod tests;
