// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::add::add_member_from_file;
use crate::feature::verify::file::verify_file_content;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::EncContent;
use crate::format::kv::enc::canonical::extract_recipients_from_wrap;
use crate::format::kv::KV_ENC_EXTENSION;
use crate::io::workspace::members::remove_member as remove_member_file;
use crate::support::fs::{list_dir, load_text_with_limit};
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

use super::types::{MemberRemovalReport, MemberRemoveResult};

pub fn add_member(options: &CommonCommandOptions, filename: &Path, force: bool) -> Result<String> {
    let workspace = require_workspace(options, "member add")?;
    add_member_from_file(&workspace.root_path, filename, force)
}

pub fn evaluate_member_removal(
    options: &CommonCommandOptions,
    member_id: &str,
) -> Result<MemberRemovalReport> {
    let workspace = require_workspace(options, "member remove")?;
    let active_member = workspace
        .root_path
        .join("members")
        .join("active")
        .join(format!("{member_id}.json"));
    if !active_member.exists() {
        return Err(Error::build_not_found_error(format!(
            "Member '{}' not found in active/",
            member_id
        )));
    }

    let mut affected_artifacts = Vec::new();
    let mut warnings = Vec::new();
    for artifact_path in find_encrypted_artifacts(&workspace.root_path)? {
        match artifact_contains_member(&artifact_path, member_id) {
            Ok(true) => affected_artifacts.push(artifact_path),
            Ok(false) => {}
            Err(error) => warnings.push(format_artifact_warning(&artifact_path, &error)),
        }
    }

    Ok(MemberRemovalReport {
        member_id: member_id.to_string(),
        affected_artifacts,
        warnings,
    })
}

pub fn remove_member(
    options: &CommonCommandOptions,
    member_id: &str,
) -> Result<MemberRemoveResult> {
    let workspace = require_workspace(options, "member remove")?;
    remove_member_file(&workspace.root_path, member_id)?;
    Ok(MemberRemoveResult {
        member_id: member_id.to_string(),
    })
}

fn find_encrypted_artifacts(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let secrets_dir = workspace_root.join("secrets");
    let entries = list_dir(&secrets_dir)?;
    let mut paths = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_encrypted_artifact(path))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn is_encrypted_artifact(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(KV_ENC_EXTENSION) || name.ends_with(".json") || name.ends_with(".encrypted")
}

fn artifact_contains_member(path: &Path, member_id: &str) -> Result<bool> {
    let content = load_text_with_limit(
        path,
        resolve_encrypted_artifact_read_limit(path),
        "encrypted artifact",
    )?;
    let recipients = verified_artifact_recipients(content)?;
    Ok(recipients.iter().any(|recipient| recipient == member_id))
}

fn verified_artifact_recipients(content: String) -> Result<Vec<String>> {
    match EncContent::detect(content)? {
        EncContent::FileEnc(file_content) => Ok(verify_file_content(&file_content, false)?
            .document()
            .recipients()),
        EncContent::KvEnc(kv_content) => Ok(extract_recipients_from_wrap(
            verify_kv_content(&kv_content, false)?.document().wrap(),
        )),
    }
}

fn format_artifact_warning(path: &Path, error: &Error) -> String {
    format!(
        "Skipping encrypted artifact '{}': {}",
        format_path_relative_to_cwd(path),
        error.format_user_message()
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/app_member_mutation_test.rs"]
mod tests;
