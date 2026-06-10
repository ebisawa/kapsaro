// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace setup and validation helpers.

use crate::model::public_key::PublicKey;
use crate::support::fs::{
    atomic,
    policy::{ensure_real_directory_tree, is_real_dir, DirectoryMode, DirectoryPurpose},
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;

fn save_gitkeep(dir: &Path) -> Result<()> {
    atomic::save_text(&dir.join(".gitkeep"), "")
}

/// Ensure workspace structure exists - create if missing.
pub fn ensure_workspace_structure(workspace_path: &Path) -> Result<bool> {
    let members_dir = workspace_path.join("members");
    let active_dir = workspace_path.join("members").join("active");
    let incoming_dir = workspace_path.join("members").join("incoming");
    let secrets_dir = workspace_path.join("secrets");
    let required_dir_tree = [
        workspace_path,
        members_dir.as_path(),
        active_dir.as_path(),
        incoming_dir.as_path(),
        secrets_dir.as_path(),
    ];
    let required_dirs = [&active_dir, &incoming_dir, &secrets_dir];

    if required_dir_tree.iter().all(|dir| is_real_dir(dir)) {
        return Ok(false);
    }

    for dir in required_dir_tree {
        ensure_workspace_dir(dir)?;
    }
    for dir in required_dirs {
        save_gitkeep(dir)?;
    }

    Ok(true)
}

/// Return true when the workspace already has at least one active member file.
pub fn check_workspace_has_active_members(workspace_path: &Path) -> Result<bool> {
    let active_dir = workspace_path.join("members").join("active");
    if !is_real_dir(&active_dir) {
        return Ok(false);
    }

    for entry in std::fs::read_dir(&active_dir).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read active members directory {}: {}",
                format_path_relative_to_cwd(&active_dir),
                e
            ),
            e,
        )
    })? {
        let entry = entry.map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to read active member entry in {}: {}",
                    format_path_relative_to_cwd(&active_dir),
                    e
                ),
                e,
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Verify that workspace structure already exists.
pub fn validate_workspace_exists(workspace_path: &Path) -> Result<()> {
    let members_dir = workspace_path.join("members");
    let members_active_dir = members_dir.join("active");
    let secrets_dir = workspace_path.join("secrets");

    if !(is_real_dir(workspace_path)
        && is_real_dir(&members_dir)
        && is_real_dir(&members_active_dir)
        && is_real_dir(&secrets_dir))
    {
        return Err(Error::build_config_error(format!(
            "Workspace not found or incomplete.\n\
             Path: {}\n\
             Action: Run kapsaro init to create a workspace.",
            format_path_relative_to_cwd(workspace_path)
        )));
    }

    Ok(())
}

/// Save a public key document into the workspace members directory.
pub fn save_member_document(member_file: &Path, public_key: &PublicKey) -> Result<()> {
    atomic::save_json(member_file, public_key)
}

fn ensure_workspace_dir(path: &Path) -> Result<()> {
    ensure_real_directory_tree(path, DirectoryPurpose::Workspace, DirectoryMode::Normal)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_init_test.rs"]
mod feature_init_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_setup_test.rs"]
mod io_workspace_setup_test;
