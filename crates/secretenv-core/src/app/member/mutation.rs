// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::artifact::{
    artifact_recipient_evidence, list_workspace_encrypted_artifacts, load_artifact_content,
    verify_artifact_signature_for_operation,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::add::add_member_from_file;
use crate::format::content::EncContent;
use crate::io::workspace::members::remove_member as remove_member_file;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use tracing::debug;

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
    for artifact_path in list_workspace_encrypted_artifacts(&workspace.root_path)? {
        match artifact_contains_member(
            &artifact_path,
            member_handle,
            options.allow_expired_key,
            options.debug,
        ) {
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

struct ArtifactMemberScan {
    contains_member: bool,
    warnings: Vec<String>,
}

fn artifact_contains_member(
    path: &Path,
    member_handle: &str,
    allow_expired_key: bool,
    debug_enabled: bool,
) -> Result<ArtifactMemberScan> {
    if debug_enabled {
        debug!(
            "[MEMBER] remove scan: verify artifact path={}",
            format_path_relative_to_cwd(path)
        );
    }
    let content = load_artifact_content(path)?;
    let result = verified_artifact_recipients(&content, allow_expired_key, debug_enabled)?;
    let contains_member = result
        .recipients
        .iter()
        .any(|recipient| recipient == member_handle);
    if debug_enabled {
        debug!(
            "[MEMBER] remove scan: artifact recipients={} contains_target={}",
            result.recipients.len(),
            contains_member
        );
    }
    Ok(ArtifactMemberScan {
        contains_member,
        warnings: result.warnings,
    })
}

struct VerifiedArtifactRecipients {
    recipients: Vec<String>,
    warnings: Vec<String>,
}

fn verified_artifact_recipients(
    content: &EncContent,
    allow_expired_key: bool,
    debug_enabled: bool,
) -> Result<VerifiedArtifactRecipients> {
    if debug_enabled {
        let artifact_type = match content {
            EncContent::FileEnc(_) => "file",
            EncContent::KvEnc(_) => "kv",
        };
        debug!("[MEMBER] remove scan: detected {artifact_type} artifact");
    }
    let proof = verify_artifact_signature_for_operation(content, debug_enabled, allow_expired_key)?;
    let evidence = artifact_recipient_evidence(content)?;
    Ok(VerifiedArtifactRecipients {
        recipients: evidence.recipient_handles,
        warnings: proof.warnings,
    })
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
