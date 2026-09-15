// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed output directories for encrypted artifacts and plaintext.
//! Preserves global protection through creation and atomic publication.

use crate::service::workspace::{WorkspaceAccess, WorkspaceCreationTarget, WorkspaceKind};
use crate::support::fs::relative::{
    directory_is_within, open_dir_nofollow, optional_child_type_at, save_bytes_at,
    save_bytes_restricted_at, ChildType, DirectoryFd, DirectoryScope, OpenDir,
};
use crate::support::path::format_finding_path;
use crate::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

/// An output name bound to an existing parent or a fixed creation ancestor.
pub struct FileOutputTarget {
    parent: OutputParent,
    path: PathBuf,
    name: String,
}

enum OutputParent {
    Existing(OpenDir),
    Missing(WorkspaceCreationTarget),
}

impl FileOutputTarget {
    /// Select output storage without creating files or missing directories.
    pub fn open(path: impl AsRef<Path>, global: Option<&WorkspaceCreationTarget>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                Error::build_invalid_argument_error("Output requires a UTF-8 file name")
            })?
            .to_owned();
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = match open_dir_nofollow(parent_path, DirectoryScope::Generic) {
            Ok(dir) => {
                let scope = if global
                    .map(|global| global.contains_directory(&dir))
                    .transpose()?
                    .unwrap_or(false)
                {
                    DirectoryScope::GlobalWorkspace
                } else {
                    DirectoryScope::Generic
                };
                enforce_output_entry(&dir, &name)?;
                OutputParent::Existing(dir.with_scope(scope))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let target = WorkspaceCreationTarget::open(parent_path, WorkspaceKind::Regular)?;
                let kind = if global
                    .map(|global| global.contains_target(&target))
                    .transpose()?
                    .unwrap_or(false)
                {
                    WorkspaceKind::Global
                } else {
                    WorkspaceKind::Regular
                };
                OutputParent::Missing(target.with_kind(kind)?)
            }
            Err(error) => return Err(error),
        };
        Ok(Self { parent, path, name })
    }

    /// Display path originally selected by the caller.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn save(&self, bytes: &[u8], secret: bool) -> Result<()> {
        match &self.parent {
            OutputParent::Existing(parent) => save_output(parent, &self.name, bytes, secret),
            OutputParent::Missing(target) => {
                save_output(target.ensure()?.directory(), &self.name, bytes, secret)
            }
        }
    }
}

pub(crate) fn output_scope<D: DirectoryFd>(
    parent: &D,
    global: Option<&WorkspaceAccess>,
) -> Result<DirectoryScope> {
    if let Some(global) = global {
        if global.kind() == WorkspaceKind::Global
            && directory_is_within(parent, global.directory())?
        {
            return Ok(DirectoryScope::GlobalWorkspace);
        }
    }
    Ok(parent.scope())
}

fn enforce_output_entry<D: DirectoryFd>(parent: &D, name: &str) -> Result<()> {
    match optional_child_type_at(parent, name)? {
        None | Some(ChildType::RegularFile) => Ok(()),
        Some(kind) => {
            let description = match kind {
                ChildType::Symlink => "symlink",
                ChildType::Directory => "directory",
                _ => "special file",
            };
            Err(Error::build_invalid_operation_error(format!(
                "refusing to write: target is a {description}: {}",
                format_finding_path(&parent.path().join(name))
            )))
        }
    }
}

fn save_output<D: DirectoryFd>(parent: &D, name: &str, bytes: &[u8], secret: bool) -> Result<()> {
    enforce_output_entry(parent, name)?;
    if secret {
        save_bytes_restricted_at(parent, name, bytes)
    } else {
        save_bytes_at(parent, name, bytes)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/service_file_output_test.rs"]
mod service_file_output_test;
