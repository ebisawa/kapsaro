// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! App-layer encrypted artifact file helpers.
//! Owns workspace artifact discovery and reviewed file loading.

use std::path::{Path, PathBuf};

use crate::app::context::review::ReviewedTextFile;
use crate::format::content::EncContent;
use crate::format::kv::KV_ENC_EXTENSION;
use crate::support::fs::list_dir;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

pub(crate) fn list_workspace_encrypted_artifacts(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let secrets_dir = workspace_root.join("secrets");
    let entries = list_dir(&secrets_dir)
        .map_err(|e| Error::build_io_error(format!("Failed to read secrets directory: {}", e)))?;

    let mut paths = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_encrypted_artifact_file(path))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

pub(crate) fn is_encrypted_artifact_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    is_encrypted_artifact_name(path)
}

fn is_encrypted_artifact_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(KV_ENC_EXTENSION) || name.ends_with(".json") || name.ends_with(".encrypted")
}

pub(crate) fn load_reviewed_artifact(path: &Path) -> Result<ReviewedTextFile> {
    ReviewedTextFile::load_existing(
        path,
        "encrypted artifact",
        resolve_encrypted_artifact_read_limit(path),
    )
}

pub(crate) fn detect_reviewed_artifact(captured: &ReviewedTextFile) -> Result<EncContent> {
    EncContent::detect_with_source(
        captured.require_content()?.to_string(),
        format_path_relative_to_cwd(captured.path()),
    )
}

pub(crate) fn load_artifact_content(path: &Path) -> Result<EncContent> {
    detect_reviewed_artifact(&load_reviewed_artifact(path)?)
}

#[cfg(test)]
#[path = "../../tests/unit/internal/app_artifact_test.rs"]
mod tests;
