// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for registration commands.

use std::path::Path;

use crate::app::registration::types::RegistrationMode;
use crate::support::path::format_path_relative_to_cwd;

pub(crate) fn print_created_workspace_summary(workspace_path: &Path) {
    eprintln!(
        "Creating workspace {}",
        format_workspace_display(workspace_path)
    );
    eprintln!("  Created members/active/");
    eprintln!("  Created members/incoming/");
    eprintln!("  Created secrets/");
}

pub(crate) fn print_init_noop_summary(workspace_path: &Path) {
    eprintln!(
        "Workspace already initialized at {}",
        format_workspace_display(workspace_path)
    );
    eprintln!("`secretenv init` only bootstraps a new workspace and first member.");
    eprintln!("Use `secretenv join` to submit a key to an existing workspace.");
}

pub(crate) fn print_registration_next_steps(mode: RegistrationMode, is_new_workspace: bool) {
    match mode {
        RegistrationMode::Init if is_new_workspace => {
            eprintln!("Ready! Commit .secretenv/ to your repository.");
        }
        RegistrationMode::Init | RegistrationMode::Join => {
            eprintln!("Ready! Create a PR to share your public key with the team.");
            if mode == RegistrationMode::Join {
                eprintln!(
                    "An active member needs to run 'secretenv rewrap' to promote the incoming key and sync secrets."
                );
            }
        }
    }
}

fn format_workspace_display(path: &Path) -> String {
    format!("{}/", format_path_relative_to_cwd(path))
}
