// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace setup and validation helpers.
//! Builds the workspace tree on directory descriptors and reports what already stands there.

use crate::io::workspace::members::{ACTIVE_DIR_NAME, INCOMING_DIR_NAME, MEMBERS_DIR_NAME};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{
    format_unreplaceable_child_type, optional_child_type_at, save_text_at, DirectoryFd,
    DirectoryScope,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

/// Name of the workspace secrets directory holding encrypted artifacts.
pub const SECRETS_DIR_NAME: &str = "secrets";

/// Validate all existing layout entries before completing the fixed root.
pub(crate) fn ensure_workspace_structure_at(root: &AnchoredDir) -> Result<bool> {
    let complete = inspect_workspace_structure_at(root)?;
    if complete {
        return Ok(false);
    }
    let members = root.ensure_child(MEMBERS_DIR_NAME)?;
    let leaves = [
        members.ensure_child(ACTIVE_DIR_NAME)?,
        members.ensure_child(INCOMING_DIR_NAME)?,
        root.ensure_child(SECRETS_DIR_NAME)?,
    ];
    for leaf in &leaves {
        if optional_child_type_at(leaf, ".gitkeep")?.is_none() {
            save_text_at(leaf, ".gitkeep", "")?;
        }
    }
    Ok(true)
}

/// Check the layout through the selected descriptor without reopening its path.
pub(crate) fn validate_workspace_exists_at(root: &AnchoredDir) -> Result<()> {
    if inspect_workspace_layout_at(root, root.scope() == DirectoryScope::GlobalWorkspace)? {
        return Ok(());
    }
    Err(Error::build_config_error(format!(
        "Workspace not found or incomplete. Path: {}. Action: Run kapsaro init{}.",
        format_path_relative_to_cwd(root.path()),
        if root.scope() == DirectoryScope::GlobalWorkspace {
            " --global"
        } else {
            ""
        },
    )))
}

pub(crate) fn inspect_workspace_structure_at(root: &AnchoredDir) -> Result<bool> {
    inspect_workspace_layout_at(root, true)
}

fn inspect_workspace_layout_at(root: &AnchoredDir, require_incoming: bool) -> Result<bool> {
    let members = inspect_layout_child(root, MEMBERS_DIR_NAME)?;
    let secrets = inspect_layout_child(root, SECRETS_DIR_NAME)?;
    let mut complete = members.is_some() && secrets.is_some();
    if let Some(members) = members {
        complete &= inspect_layout_child(&members, ACTIVE_DIR_NAME)?.is_some();
        let incoming = inspect_layout_child(&members, INCOMING_DIR_NAME)?;
        complete &= !require_incoming || incoming.is_some();
    }
    Ok(complete)
}

fn inspect_layout_child(parent: &AnchoredDir, name: &str) -> Result<Option<AnchoredDir>> {
    if optional_child_type_at(parent, name)?.is_none() {
        return Ok(None);
    }
    let child = parent.open_child(name)?;
    if let Some(kind) =
        optional_child_type_at(&child, ".gitkeep")?.and_then(format_unreplaceable_child_type)
    {
        return Err(Error::build_invalid_operation_error(format!(
            "Invalid workspace placeholder ({kind}): {}",
            format_path_relative_to_cwd(&child.path().join(".gitkeep"))
        )));
    }
    Ok(Some(child))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_setup_creation_test.rs"]
mod io_workspace_setup_creation_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_setup_test.rs"]
mod io_workspace_setup_test;
