// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV command session binding.
//! Resolves the target file inside a workspace and reads the content a command acts on.

use std::path::PathBuf;
use std::sync::Arc;

use crate::app::context::execution::{build_write_execution_warnings, ExecutionContext};
#[cfg(test)]
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::build_workspace_not_found_error;
#[cfg(test)]
use crate::app::context::paths::require_workspace;
use crate::app::context::review::ReviewedTextFile;
use crate::format::content::KvEncContent;
use crate::format::kv::{DEFAULT_KV_ENC_BASENAME, KV_ENC_EXTENSION};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryFd;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::validation::validate_kv_file_basename;
use crate::{Error, Result};

/// Label the KV target carries in messages about a review that no longer holds.
pub(super) const KV_FILE_SUBJECT_LABEL: &str = "KV file";

#[derive(Debug, Clone)]
pub struct KvFileTarget {
    pub file_path: PathBuf,
    /// The entry name below the secrets directory, for descriptor-relative work.
    pub file_name: String,
}

impl KvFileTarget {
    #[cfg(test)]
    pub(super) fn resolve(options: &CommonCommandOptions, file_name: Option<&str>) -> Result<Self> {
        let workspace_root = require_workspace(options, "kv access")?;
        let file_name = kv_file_name(file_name)?;
        let file_path = workspace_root.secrets_dir().join(&file_name);

        Ok(Self {
            file_path,
            file_name,
        })
    }

    /// Name the target through the directories the execution already fixed.
    ///
    /// A mutation replaces the file through the secrets directory descriptor the
    /// execution holds, so resolving the workspace a second time here would let
    /// the review, the member snapshot and the write name three different trees
    /// when the workspace is repointed mid-command. All of them now come from
    /// the one workspace the execution bound to.
    ///
    /// The workspace is required first so a run outside one is reported as
    /// what it is; opening the secrets directory would otherwise name a missing
    /// capability instead.
    pub(super) fn bind(execution: &ExecutionContext, file_name: Option<&str>) -> Result<Self> {
        fixed_kv_workspace(execution)?;
        let file_name = kv_file_name(file_name)?;
        let file_path = execution
            .ensured_secrets_directory()?
            .path()
            .join(&file_name);

        Ok(Self {
            file_path,
            file_name,
        })
    }
}

/// The file name a KV command acts on, defaulted and validated.
fn kv_file_name(file_name: Option<&str>) -> Result<String> {
    let name = match file_name {
        Some(supplied) => {
            validate_kv_file_basename(supplied)?;
            supplied
        }
        None => DEFAULT_KV_ENC_BASENAME,
    };
    Ok(format!("{name}{KV_ENC_EXTENSION}"))
}

/// The workspace the execution fixed.
///
/// An execution binds a workspace directory exactly when it resolved one, so the
/// only way to arrive here without one is to run a KV command outside a
/// workspace, which is reported as such rather than as a missing capability.
fn fixed_kv_workspace(execution: &ExecutionContext) -> Result<&AnchoredDir> {
    execution
        .fixed_workspace_directory()
        .map_err(|_| build_workspace_not_found_error("kv access"))
}

/// One KV command bound to the target file and the identity it acts as.
pub struct KvCommandSession<'a> {
    pub target: KvFileTarget,
    pub execution: &'a ExecutionContext,
    pub warnings: Vec<String>,
}

impl<'a> KvCommandSession<'a> {
    pub fn bind_write(execution: &'a ExecutionContext, file_name: Option<&str>) -> Result<Self> {
        let target = KvFileTarget::bind(execution, file_name)?;
        let warnings = build_write_execution_warnings(execution)?;
        Ok(Self {
            target,
            execution,
            warnings,
        })
    }
}

/// Read the target once and keep the descriptors the read came from.
///
/// The read is addressed to the secrets directory the execution already fixed,
/// so the capture, every re-check built on it and the write that follows all
/// speak about the one tree the command bound to. The same capture answers both
/// what the command acts on and what a later re-check compares against, so the
/// content that was reviewed is the content of the file being replaced.
pub(super) fn capture_reviewed_target(
    execution: &ExecutionContext,
    target: &KvFileTarget,
    allow_missing: bool,
) -> Result<ReviewedTextFile> {
    let reviewed = ReviewedTextFile::capture_optional_at(
        Arc::clone(execution.ensured_secrets_directory()?),
        &target.file_name,
        KV_FILE_SUBJECT_LABEL,
        resolve_encrypted_artifact_read_limit(&target.file_path),
    )?;
    if reviewed.content().is_none() && !allow_missing {
        return Err(Error::build_config_error(format!(
            "File not found: {}",
            target.file_path.display()
        )));
    }
    Ok(reviewed)
}

/// The KV document the capture holds, absent when the target was not there.
pub(super) fn reviewed_kv_content(
    target: &KvFileTarget,
    reviewed: &ReviewedTextFile,
) -> Option<KvEncContent> {
    reviewed.content().map(|content| {
        KvEncContent::new_unchecked_with_source(
            content.to_string(),
            format_path_relative_to_cwd(&target.file_path),
        )
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_kv_session_test.rs"]
mod app_kv_session_test;
