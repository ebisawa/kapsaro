// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! App-layer encrypted artifact file helpers.
//! Owns workspace artifact discovery and reviewed file loading.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::app::context::review::ReviewedTextFile;
use crate::format::content::EncContent;
use crate::format::kv::KV_ENC_EXTENSION;
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::support::fs::relative::{
    open_child_dir, open_dir_nofollow, regular_file_exists_at, scan_child_entries_at, ChildName,
    ChildType, DirectoryFd, DirectoryScope, OpenDir, ScanBudget, ScannedChild,
};
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};
use crate::{Error, Result};

/// One encrypted artifact, bound to the directory descriptor it was found under.
///
/// A name on its own says nothing about which tree it belongs to. Holding the
/// directory open means every later step — reading, planning, locking, writing —
/// reaches the entry the listing actually saw, even when the path that named the
/// directory is repointed at another tree while the command runs.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactRef {
    dir: Arc<OpenDir>,
    name: String,
    display_path: PathBuf,
}

impl ArtifactRef {
    /// A scanned child of a directory the caller already holds open.
    pub(crate) fn in_open_dir(dir: Arc<OpenDir>, name: String) -> Self {
        let display_path = dir.path().join(&name);
        Self {
            dir,
            name,
            display_path,
        }
    }

    /// A target the operator named, bound by opening its parent directory.
    ///
    /// The parent is opened refusing a final symlink, so a link standing in for
    /// the directory is reported while the run is still planning rather than
    /// once the replacement is about to be written.
    pub(crate) fn open_from_path(path: &Path) -> Result<Self> {
        let name = artifact_target_name(path)?;
        let dir = open_dir_nofollow(&artifact_target_parent(path), DirectoryScope::Generic)?;
        if !regular_file_exists_at(&dir, &name)? {
            return Err(Error::build_not_found_error(format!(
                "Failed to read file {}: no such file",
                format_path_relative_to_cwd(path)
            )));
        }
        Ok(Self {
            dir: Arc::new(dir),
            name,
            display_path: path.to_path_buf(),
        })
    }

    pub(crate) fn directory(&self) -> &Arc<OpenDir> {
        &self.dir
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Display only. Never re-opened.
    pub(crate) fn path(&self) -> &Path {
        &self.display_path
    }
}

/// The single directory component a target names.
fn artifact_target_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .ok_or_else(|| {
            Error::build_invalid_argument_error(format!(
                "Artifact target names no file: {}",
                format_path_relative_to_cwd(path)
            ))
        })
}

/// The directory holding the target, as a path this process can open.
///
/// A bare file name has an empty parent rather than none, and that names the
/// working directory the target was resolved against. Turning it into `.` keeps
/// a target named without a directory reaching the same entry a read would.
fn artifact_target_parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The encrypted artifacts a workspace holds, and the entries beside them that
/// the scan could not judge.
///
/// `secrets/` is shared through git, so its contents are whatever a teammate
/// committed. One entry that cannot be inspected therefore leaves the listing
/// as a warning instead of taking every artifact next to it down with it.
pub(crate) struct WorkspaceArtifactListing {
    pub(crate) artifacts: Vec<ArtifactRef>,
    pub(crate) warnings: Vec<String>,
}

/// List the encrypted artifacts a workspace holds, under its descriptor.
///
/// `secrets/` is reached as a named child of the workspace the caller already
/// bound, and each artifact keeps that descriptor, so the artifacts a command
/// acts on come from the tree it started in even if the workspace path is
/// repointed while it runs.
///
/// The entry types come from the same walk that produced the names, so an entry
/// is judged on what the scan saw rather than on a second lookup that could
/// reach a different entry. An entry outside the naming convention is left out
/// quietly, but one with an artifact-shaped name that is not a regular file is
/// reported as a warning: the workspace declared it an artifact by naming it
/// one, and a symlink or directory standing in for it is not something a
/// listing can silently skip.
pub(crate) fn list_workspace_encrypted_artifacts_at<D>(
    workspace: &D,
) -> Result<WorkspaceArtifactListing>
where
    D: DirectoryFd,
{
    let opened =
        Arc::new(open_child_dir(workspace, SECRETS_DIR_NAME).map_err(|e| {
            Error::build_io_error(format!("Failed to read secrets directory: {}", e))
        })?);
    let mut listing = WorkspaceArtifactListing {
        artifacts: Vec::new(),
        warnings: Vec::new(),
    };
    for child in scan_child_entries_at(opened.as_ref(), ScanBudget::Unlimited)?.entries {
        collect_scanned_artifact(&opened, child, &mut listing);
    }
    listing.artifacts.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(listing)
}

/// Keep one scanned entry, or record why it was left out.
fn collect_scanned_artifact(
    dir: &Arc<OpenDir>,
    child: ScannedChild,
    listing: &mut WorkspaceArtifactListing,
) {
    let (name, child_type) = match child {
        ScannedChild::Inspected {
            name, child_type, ..
        } => (name, child_type),
        ScannedChild::Unreadable { name, error } => {
            let reason = error.format_user_message().to_string();
            listing
                .warnings
                .push(build_skipped_entry_warning(dir, &name, &reason));
            return;
        }
    };
    let Some(decoded) = name.decoded() else {
        listing.warnings.push(build_skipped_entry_warning(
            dir,
            &name,
            "entry name is not valid UTF-8",
        ));
        return;
    };
    match child_type {
        ChildType::RegularFile if is_encrypted_artifact_name(decoded) => {
            listing.artifacts.push(ArtifactRef::in_open_dir(
                Arc::clone(dir),
                decoded.to_string(),
            ));
        }
        _ if is_encrypted_artifact_name(decoded) => {
            listing.warnings.push(build_skipped_entry_warning(
                dir,
                &name,
                "entry is not a regular file",
            ));
        }
        _ => {}
    }
}

fn build_skipped_entry_warning(dir: &OpenDir, name: &ChildName, reason: &str) -> String {
    format!(
        "Skipping secrets entry '{}': {}",
        format_finding_path(&name.path_under(dir)),
        reason
    )
}

pub(crate) fn is_encrypted_artifact_name(name: &str) -> bool {
    name.ends_with(KV_ENC_EXTENSION) || name.ends_with(".json") || name.ends_with(".encrypted")
}

pub(crate) fn load_reviewed_artifact(artifact: &ArtifactRef) -> Result<ReviewedTextFile> {
    ReviewedTextFile::load_existing_at(
        Arc::clone(artifact.directory()),
        artifact.name(),
        "encrypted artifact",
        resolve_encrypted_artifact_read_limit(Path::new(artifact.name())),
    )
}

/// Parse one reviewed artifact, naming it the way every finding names it.
///
/// The name reaches the operator inside a parse failure on standard error, and
/// `secrets/` holds whatever a teammate committed, so a file name carrying a
/// newline could otherwise write a second line of its own.
pub(crate) fn detect_reviewed_artifact(captured: &ReviewedTextFile) -> Result<EncContent> {
    EncContent::detect_with_source(
        captured.require_content()?.to_string(),
        format_finding_path(captured.path()),
    )
}

pub(crate) fn load_artifact_content(artifact: &ArtifactRef) -> Result<EncContent> {
    detect_reviewed_artifact(&load_reviewed_artifact(artifact)?)
}

#[cfg(test)]
#[path = "../../tests/unit/internal/app_artifact_test.rs"]
mod tests;
