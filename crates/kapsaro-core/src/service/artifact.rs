// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Encrypted artifact file helpers for service operations.
//! Owns workspace artifact discovery and reviewed file loading.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::format::content::EncContent;
use crate::format::kv::KV_ENC_EXTENSION;
use crate::io::workspace::setup::SECRETS_DIR_NAME;
pub(crate) mod review;
pub(crate) mod verified;

use crate::service::rewrap::RewrapTarget;
use crate::support::fs::relative::{
    duplicate_open_dir, open_child_dir, scan_child_entries_at, ChildName, ChildType, DirectoryFd,
    OpenDir, ScanBudget, ScannedChild,
};
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_finding_path;
use crate::{Error, Result};
pub(crate) use review::ReviewedTextFile;

/// One encrypted artifact, bound to the directory descriptor it was found under.
///
/// A name on its own says nothing about which tree it belongs to. Holding the
/// directory open means every later step — reading, planning, locking, writing —
/// reaches the entry the listing actually saw, even when the path that named the
/// directory is repointed at another tree while the command runs.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactRef {
    dir: Arc<OpenDir>,
    parent_binding: Option<DirectoryParentBinding>,
    name: String,
    display_path: PathBuf,
}

#[derive(Debug, Clone)]
struct DirectoryParentBinding {
    parent: Arc<OpenDir>,
    child_name: String,
}

impl ArtifactRef {
    /// A scanned child of a directory the caller already holds open.
    pub(crate) fn in_open_dir(
        parent: Arc<OpenDir>,
        child_name: &str,
        dir: Arc<OpenDir>,
        name: String,
    ) -> Result<Self> {
        let display_path = dir.path().join(&name);
        let parent_binding = DirectoryParentBinding::capture(parent, child_name);
        Ok(Self {
            dir,
            parent_binding: Some(parent_binding),
            name,
            display_path,
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

    pub(crate) fn rewrap_target(&self) -> Result<RewrapTarget> {
        let binding = self.parent_binding.as_ref().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "Artifact target has no fixed parent capability".to_string(),
            )
        })?;
        RewrapTarget::from_capabilities(
            Arc::clone(&binding.parent),
            &binding.child_name,
            Arc::clone(&self.dir),
            self.name.clone(),
            self.display_path.clone(),
        )
    }
}

impl DirectoryParentBinding {
    fn capture(parent: Arc<OpenDir>, child_name: &str) -> Self {
        Self {
            parent,
            child_name: child_name.to_string(),
        }
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
    let workspace = Arc::new(duplicate_open_dir(workspace)?);
    let opened = Arc::new(
        open_child_dir(workspace.as_ref(), SECRETS_DIR_NAME).map_err(|e| {
            Error::build_io_error(format!("Failed to read secrets directory: {}", e))
        })?,
    );
    let mut listing = WorkspaceArtifactListing {
        artifacts: Vec::new(),
        warnings: Vec::new(),
    };
    for child in scan_child_entries_at(opened.as_ref(), ScanBudget::Unlimited)?.entries {
        collect_scanned_artifact(&workspace, &opened, child, &mut listing);
    }
    listing.artifacts.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(listing)
}

/// Keep one scanned entry, or record why it was left out.
fn collect_scanned_artifact(
    parent: &Arc<OpenDir>,
    dir: &Arc<OpenDir>,
    child: ScannedChild,
    listing: &mut WorkspaceArtifactListing,
) {
    let Some((name, child_type)) = inspect_scanned_child(dir, child, listing) else {
        return;
    };
    let Some(decoded) = name.decoded() else {
        listing.warnings.push(build_skipped_entry_warning(
            dir,
            &name,
            "entry name is not valid UTF-8",
        ));
        return;
    };
    if !is_encrypted_artifact_name(decoded) {
        return;
    }
    if !matches!(child_type, ChildType::RegularFile) {
        listing.warnings.push(build_skipped_entry_warning(
            dir,
            &name,
            "entry is not a regular file",
        ));
        return;
    }
    push_opened_artifact(parent, dir, &name, decoded, listing);
}

/// Open one artifact entry and record it, or record why it could not be opened.
fn push_opened_artifact(
    parent: &Arc<OpenDir>,
    dir: &Arc<OpenDir>,
    name: &ChildName,
    decoded: &str,
    listing: &mut WorkspaceArtifactListing,
) {
    match ArtifactRef::in_open_dir(
        Arc::clone(parent),
        SECRETS_DIR_NAME,
        Arc::clone(dir),
        decoded.to_string(),
    ) {
        Ok(artifact) => listing.artifacts.push(artifact),
        Err(error) => listing.warnings.push(build_skipped_entry_warning(
            dir,
            name,
            error.format_user_message(),
        )),
    }
}

/// Name one scanned entry, or record why the scan could not judge it.
fn inspect_scanned_child(
    dir: &Arc<OpenDir>,
    child: ScannedChild,
    listing: &mut WorkspaceArtifactListing,
) -> Option<(ChildName, ChildType)> {
    match child {
        ScannedChild::Inspected {
            name, child_type, ..
        } => Some((name, child_type)),
        ScannedChild::Unreadable { name, error } => {
            let reason = error.format_user_message().to_string();
            listing
                .warnings
                .push(build_skipped_entry_warning(dir, &name, &reason));
            None
        }
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
#[path = "../../tests/unit/internal/service_artifact_test.rs"]
mod service_artifact_test;
