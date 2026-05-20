// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::add::add_member_from_file;
use crate::feature::verify::file::verify_file_content_for_operation;
use crate::feature::verify::kv::signature::verify_kv_content_for_operation;
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
    member_handle: &str,
) -> Result<MemberRemovalReport> {
    let workspace = require_workspace(options, "member remove")?;
    let active_member = workspace
        .root_path
        .join("members")
        .join("active")
        .join(format!("{member_handle}.json"));
    if !active_member.exists() {
        return Err(Error::build_not_found_error(format!(
            "Member '{}' not found in active/",
            member_handle
        )));
    }

    let mut affected_artifacts = Vec::new();
    let mut warnings = Vec::new();
    for artifact_path in find_encrypted_artifacts(&workspace.root_path)? {
        match artifact_contains_member(&artifact_path, member_handle, options.allow_expired_key) {
            Ok(result) => {
                warnings.extend(result.warnings);
                if result.contains_member {
                    affected_artifacts.push(artifact_path);
                }
            }
            Err(error) if error.verification_rule() == Some("E_KEY_EXPIRED") => return Err(error),
            Err(error) => warnings.push(format_artifact_warning(&artifact_path, &error)),
        }
    }

    Ok(MemberRemovalReport {
        member_handle: member_handle.to_string(),
        affected_artifacts,
        warnings,
    })
}

pub fn remove_member(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> Result<MemberRemoveResult> {
    let workspace = require_workspace(options, "member remove")?;
    remove_member_file(&workspace.root_path, member_handle)?;
    Ok(MemberRemoveResult {
        member_handle: member_handle.to_string(),
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

struct ArtifactMemberScan {
    contains_member: bool,
    warnings: Vec<String>,
}

fn artifact_contains_member(
    path: &Path,
    member_handle: &str,
    allow_expired_key: bool,
) -> Result<ArtifactMemberScan> {
    let content = load_text_with_limit(
        path,
        resolve_encrypted_artifact_read_limit(path),
        "encrypted artifact",
    )?;
    let result = verified_artifact_recipients(
        content,
        &format_path_relative_to_cwd(path),
        allow_expired_key,
    )?;
    Ok(ArtifactMemberScan {
        contains_member: result
            .recipients
            .iter()
            .any(|recipient| recipient == member_handle),
        warnings: result.warnings,
    })
}

struct VerifiedArtifactRecipients {
    recipients: Vec<String>,
    warnings: Vec<String>,
}

fn verified_artifact_recipients(
    content: String,
    source_name: &str,
    allow_expired_key: bool,
) -> Result<VerifiedArtifactRecipients> {
    match EncContent::detect_with_source(content, source_name)? {
        EncContent::FileEnc(file_content) => {
            let verified =
                verify_file_content_for_operation(&file_content, false, allow_expired_key)?;
            Ok(VerifiedArtifactRecipients {
                recipients: verified.document().recipients(),
                warnings: verified.proof.warnings,
            })
        }
        EncContent::KvEnc(kv_content) => {
            let verified = verify_kv_content_for_operation(&kv_content, false, allow_expired_key)?;
            Ok(VerifiedArtifactRecipients {
                recipients: extract_recipients_from_wrap(verified.document().wrap()),
                warnings: verified.proof.warnings,
            })
        }
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
#[path = "../../../tests/unit/internal/app_member_mutation_test.rs"]
mod tests;
