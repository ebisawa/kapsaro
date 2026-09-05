// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace setup and validation helpers.
//! Builds the workspace tree on directory descriptors and reports what already stands there.

use crate::io::workspace::members::{
    has_member_document_extension, ACTIVE_DIR_NAME, INCOMING_DIR_NAME, MEMBERS_DIR_NAME,
};
use crate::support::fs::policy::{ensure_real_directory_tree, is_real_dir, DirectoryKind};
use crate::support::fs::relative::{
    ensure_scoped_child_dir_at, format_unreplaceable_child_type, list_child_entries_at,
    open_dir_nofollow, optional_child_type_at, save_text_at, ChildType, DirectoryFd,
    DirectoryScope, OpenDir,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;

/// Name of the workspace secrets directory holding encrypted artifacts.
pub const SECRETS_DIR_NAME: &str = "secrets";

/// Ensure workspace structure exists - create if missing.
pub fn ensure_workspace_structure(workspace_path: &Path) -> Result<bool> {
    if workspace_tree_complete(workspace_path)? {
        return Ok(false);
    }
    ensure_workspace_dir(workspace_path)?;
    let root = open_dir_nofollow(workspace_path, DirectoryScope::Generic)?;
    let members = ensure_scoped_child_dir_at(&root, MEMBERS_DIR_NAME)?;
    let leaves = [
        ensure_scoped_child_dir_at(&members, ACTIVE_DIR_NAME)?,
        ensure_scoped_child_dir_at(&members, INCOMING_DIR_NAME)?,
        ensure_scoped_child_dir_at(&root, SECRETS_DIR_NAME)?,
    ];
    for leaf in &leaves {
        save_gitkeep(leaf)?;
    }
    Ok(true)
}

/// Whether every directory the workspace layout requires is already a real one.
fn workspace_tree_complete(workspace_path: &Path) -> Result<bool> {
    let members_dir = workspace_path.join(MEMBERS_DIR_NAME);
    for dir in [
        workspace_path,
        members_dir.as_path(),
        &members_dir.join(ACTIVE_DIR_NAME),
        &members_dir.join(INCOMING_DIR_NAME),
        &workspace_path.join(SECRETS_DIR_NAME),
    ] {
        if !is_real_dir(dir)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Return true when the workspace already has at least one active member file.
pub fn check_workspace_has_active_members(workspace_path: &Path) -> Result<bool> {
    let active_dir = workspace_path.join(MEMBERS_DIR_NAME).join(ACTIVE_DIR_NAME);
    if !is_real_dir(&active_dir)? {
        return Ok(false);
    }
    let opened = open_dir_nofollow(&active_dir, DirectoryScope::Generic)?;
    holds_member_document(&opened)
}

/// Whether the directory holds a member document rather than only placeholders.
///
/// Only a regular file counts: an entry of another type is not a document
/// kapsaro wrote, and treating it as one would report a membership that cannot
/// be read.
fn holds_member_document(dir: &OpenDir) -> Result<bool> {
    Ok(list_child_entries_at(dir)?
        .iter()
        .any(|(name, child_type)| {
            *child_type == ChildType::RegularFile && has_member_document_extension(name)
        }))
}

/// Verify that workspace structure already exists.
pub fn validate_workspace_exists(workspace_path: &Path) -> Result<()> {
    let members_dir = workspace_path.join(MEMBERS_DIR_NAME);
    let present = is_real_dir(workspace_path)?
        && is_real_dir(&members_dir)?
        && is_real_dir(&members_dir.join(ACTIVE_DIR_NAME))?
        && is_real_dir(&workspace_path.join(SECRETS_DIR_NAME))?;
    if present {
        return Ok(());
    }
    Err(Error::build_config_error(format!(
        "Workspace not found or incomplete.\n\
         Path: {}\n\
         Action: Run kapsaro init to create a workspace.",
        format_path_relative_to_cwd(workspace_path)
    )))
}

/// Place the directory's `.gitkeep`, refusing a name the write must not take over.
///
/// The write stages a fresh entry and renames it into place, so anything but a
/// regular file standing at the name would be replaced rather than written
/// through. Every one of them is refused instead: the entry is the only sign the
/// name was repointed, and the rename erases that.
fn save_gitkeep(dir: &OpenDir) -> Result<()> {
    let name = ".gitkeep";
    if let Some(description) =
        optional_child_type_at(dir, name)?.and_then(format_unreplaceable_child_type)
    {
        return Err(Error::build_invalid_operation_error(format!(
            "refusing to replace {} standing where a workspace document belongs: {}",
            description,
            format_path_relative_to_cwd(&dir.path().join(name))
        )));
    }
    save_text_at(dir, name, "")
}

fn ensure_workspace_dir(path: &Path) -> Result<()> {
    ensure_real_directory_tree(path, DirectoryKind::Workspace)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_setup_creation_test.rs"]
mod io_workspace_setup_creation_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_setup_test.rs"]
mod io_workspace_setup_test;
