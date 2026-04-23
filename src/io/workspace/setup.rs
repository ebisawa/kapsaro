// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace setup and validation helpers.

use crate::model::public_key::PublicKey;
use crate::support::fs::atomic;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

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

    if !(is_real_dir(workspace_path)
        && is_real_dir(&members_dir)
        && is_real_dir(&members_active_dir)
        && is_real_dir(&secrets_dir))
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

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            let file_type = metadata.file_type();
            file_type.is_dir() && !file_type.is_symlink()
        })
        .unwrap_or(false)
}

fn ensure_workspace_dir(path: &Path) -> Result<()> {
    for missing_dir in collect_missing_directories(path)?.into_iter().rev() {
        fs::create_dir(&missing_dir).map_err(|e| {
            Error::io_with_source(
                format!(
                    "Failed to create directory {}: {}",
                    display_path_relative_to_cwd(&missing_dir),
                    e
                ),
                e,
            )
        })?;
    }
    Ok(())
}

fn collect_missing_directories(path: &Path) -> Result<Vec<PathBuf>> {
    let mut missing = Vec::new();

    for ancestor in path.ancestors() {
        let candidate = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                validate_workspace_directory(candidate, &metadata)?;
                return Ok(missing);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
            }
            Err(e) => {
                return Err(Error::io_with_source(
                    format!(
                        "Failed to inspect directory {}: {}",
                        display_path_relative_to_cwd(candidate),
                        e
                    ),
                    e,
                ));
            }
        }
    }

    Err(Error::io(format!(
        "Failed to resolve workspace directory ancestry for {}",
        display_path_relative_to_cwd(path)
    )))
}

fn validate_workspace_directory(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::InvalidOperation {
            message: format!(
                "refusing to create workspace path through symlink: {}",
                display_path_relative_to_cwd(path)
            ),
        });
    }
    if !file_type.is_dir() {
        return Err(Error::io(format!(
            "Failed to create directory {}: existing path is not a directory",
            display_path_relative_to_cwd(path)
        )));
    }
    Ok(())
}
