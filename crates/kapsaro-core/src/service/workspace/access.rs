// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed workspace roots and creation targets for explicit caller selections.
//! Retains directory identities and protection policy without resolving ambient inputs.

use std::path::{Path, PathBuf};

use crate::io::workspace::setup::validate_workspace_exists_at;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::permission::report_scoped_open_permission;
use crate::support::fs::relative::{
    directory_is_within, file_identity, DirectoryFd, DirectoryScope,
};
use crate::{Error, ErrorKind, Result};

/// Storage policy associated with a selected workspace directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceKind {
    /// A workspace shared with a repository.
    Regular,
    /// An owner-only workspace shared across the caller's projects.
    Global,
}

impl WorkspaceKind {
    fn scope(self) -> DirectoryScope {
        match self {
            Self::Regular => DirectoryScope::Generic,
            Self::Global => DirectoryScope::GlobalWorkspace,
        }
    }
}

/// Cloneable access to the directory selected by the caller.
#[derive(Clone, Debug)]
pub struct WorkspaceAccess {
    directory: AnchoredDir,
    kind: WorkspaceKind,
}

impl WorkspaceAccess {
    /// Open a selected root once, following an explicitly selected root link.
    pub fn open(path: impl Into<PathBuf>, kind: WorkspaceKind) -> Result<Self> {
        let directory = AnchoredDir::open(path, kind.scope(), "workspace root")?;
        report_scoped_open_permission(&directory, directory.file(), directory.path());
        Ok(Self { directory, kind })
    }

    /// Display path of the selection; operations retain the opened directory.
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Protection policy retained by this selection.
    pub fn kind(&self) -> WorkspaceKind {
        self.kind
    }

    /// Validate the workspace layout using the retained directory descriptor.
    pub fn validate(&self) -> Result<()> {
        validate_workspace_exists_at(&self.directory)
    }

    /// Compare opened directory identities, including selections through aliases.
    pub fn same_directory(&self, other: &Self) -> Result<bool> {
        same_directory(&self.directory, &other.directory)
    }

    /// Associate the selected identity with a caller-resolved protection policy.
    pub fn with_kind(&self, kind: WorkspaceKind) -> Result<Self> {
        let directory = self.directory.with_scope(kind.scope())?;
        report_scoped_open_permission(&directory, directory.file(), directory.path());
        Ok(Self { directory, kind })
    }

    pub(crate) fn directory(&self) -> &AnchoredDir {
        &self.directory
    }
}

/// A fixed existing ancestor and the path components initialization may create.
#[derive(Clone, Debug)]
pub struct WorkspaceCreationTarget {
    path: PathBuf,
    kind: WorkspaceKind,
    ancestor: AnchoredDir,
    missing: Vec<String>,
    existing: Option<WorkspaceAccess>,
}

impl WorkspaceCreationTarget {
    /// Resolve the existing ancestor without creating any directory.
    pub fn open(path: impl Into<PathBuf>, kind: WorkspaceKind) -> Result<Self> {
        let path = path.into();
        let mut ancestor_path = path.clone();
        let mut missing = Vec::new();
        let ancestor = loop {
            match AnchoredDir::open(
                &ancestor_path,
                DirectoryScope::Generic,
                "workspace creation ancestor",
            ) {
                Ok(directory) => break directory,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    let name = ancestor_path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| {
                            Error::build_invalid_argument_error(
                                "Workspace creation requires valid path components",
                            )
                        })?;
                    missing.push(name.to_owned());
                    if !ancestor_path.pop() {
                        return Err(error);
                    }
                    if ancestor_path.as_os_str().is_empty() {
                        ancestor_path.push(".");
                    }
                }
                Err(error) => return Err(error),
            }
        };
        missing.reverse();
        let existing = if missing.is_empty() {
            Some(WorkspaceAccess {
                directory: ancestor.with_scope(kind.scope())?,
                kind,
            })
        } else {
            None
        };
        Ok(Self {
            path,
            kind,
            ancestor,
            missing,
            existing,
        })
    }

    /// Display path selected for initialization.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Protection policy retained by this target.
    pub fn kind(&self) -> WorkspaceKind {
        self.kind
    }

    /// Access to a root that already existed at selection time.
    pub fn existing_access(&self) -> Option<&WorkspaceAccess> {
        self.existing.as_ref()
    }

    pub(crate) fn contains_target(&self, other: &Self) -> Result<bool> {
        if same_directory(&self.ancestor, &other.ancestor)?
            && other.missing.starts_with(&self.missing)
        {
            return Ok(true);
        }
        self.contains_directory(&other.ancestor)
    }

    pub(crate) fn contains_directory<D: DirectoryFd>(&self, directory: &D) -> Result<bool> {
        let mut root = self.ancestor.clone();
        for name in &self.missing {
            root = match root.open_child(name) {
                Ok(child) => child,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
        }
        directory_is_within(directory, &root.with_scope(self.kind.scope())?)
    }

    /// Keep the fixed selection while applying its resolved storage policy.
    pub fn with_kind(&self, kind: WorkspaceKind) -> Result<Self> {
        Ok(Self {
            path: self.path.clone(),
            kind,
            ancestor: self.ancestor.clone(),
            missing: self.missing.clone(),
            existing: self
                .existing
                .as_ref()
                .map(|access| access.with_kind(kind))
                .transpose()?,
        })
    }

    /// Compare fixed ancestors and remaining components without creating them.
    pub fn same_target(&self, other: &Self) -> Result<bool> {
        Ok(self.missing == other.missing && same_directory(&self.ancestor, &other.ancestor)?)
    }

    /// Create missing components relative to the original ancestor capability.
    pub fn ensure(&self) -> Result<WorkspaceAccess> {
        let mut directory = self.ancestor.clone();
        for name in &self.missing {
            directory = directory.ensure_child_with_scope(name, self.kind.scope())?;
        }
        Ok(WorkspaceAccess {
            directory: directory.with_scope(self.kind.scope())?,
            kind: self.kind,
        })
    }
}

fn same_directory(left: &AnchoredDir, right: &AnchoredDir) -> Result<bool> {
    Ok(file_identity(left.file(), left.path())? == file_identity(right.file(), right.path())?)
}
