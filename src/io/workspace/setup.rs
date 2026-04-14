// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace setup and validation helpers.

use crate::model::public_key::PublicKey;
use crate::support::fs::{atomic, ensure_dir};
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;

fn save_gitkeep(dir: &Path) -> Result<()> {
    std::fs::write(dir.join(".gitkeep"), "").map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to create .gitkeep in {}: {}",
                display_path_relative_to_cwd(dir),
                e
            ),
            e,
        )
    })
}

/// Ensure workspace structure exists - create if missing.
pub fn ensure_workspace_structure(workspace_path: &Path) -> Result<bool> {
    let active_dir = workspace_path.join("members").join("active");
    let incoming_dir = workspace_path.join("members").join("incoming");
    let secrets_dir = workspace_path.join("secrets");
    let required_dirs = [&active_dir, &incoming_dir, &secrets_dir];

    if required_dirs.iter().all(|dir| dir.exists()) {
        return Ok(false);
    }

    for dir in required_dirs {
        ensure_dir(dir)?;
        save_gitkeep(dir)?;
    }

    Ok(true)
}

/// Return true when the workspace already has at least one active member file.
pub fn workspace_has_active_members(workspace_path: &Path) -> Result<bool> {
    let active_dir = workspace_path.join("members").join("active");
    if !active_dir.is_dir() {
        return Ok(false);
    }

    for entry in std::fs::read_dir(&active_dir).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read active members directory {}: {}",
                display_path_relative_to_cwd(&active_dir),
                e
            ),
            e,
        )
    })? {
        let entry = entry.map_err(|e| {
            Error::io_with_source(
                format!(
                    "Failed to read active member entry in {}: {}",
                    display_path_relative_to_cwd(&active_dir),
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

    if !workspace_path.exists()
        || !members_dir.exists()
        || !members_active_dir.exists()
        || !secrets_dir.exists()
    {
        return Err(Error::Config {
            message: format!(
                "Workspace not found or incomplete: {}. Run 'secretenv init' to create a new workspace.",
                display_path_relative_to_cwd(workspace_path)
            ),
        });
    }

    Ok(())
}

/// Save a public key document into the workspace members directory.
pub fn save_member_document(member_file: &Path, public_key: &PublicKey) -> Result<()> {
    atomic::save_json(member_file, public_key)
}
