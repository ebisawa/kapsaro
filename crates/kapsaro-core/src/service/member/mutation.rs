// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace member addition and removal use cases.
//! Reports which artifacts a removal would affect before the member is dropped.

use std::path::{Path, PathBuf};

use crate::feature::artifact::{
    artifact_recipient_evidence, verify_artifact_signature_for_operation,
};
use crate::feature::member::add::build_member_addition_from_content;
use crate::format::content::EncContent;
use crate::io::workspace::members::{
    review_active_member_document, save_member_content, MemberStatus,
};
use crate::service::artifact::{
    list_workspace_encrypted_artifacts_at, load_artifact_content, ArtifactRef,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::load_text_with_limit;
use crate::support::fs::relative::DirectoryScope;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, ErrorKind, Result};
use tracing::debug;

use super::types::{MemberRemovalReport, MemberRemoveResult};

/// Stage a public key document as an incoming member of the workspace.
///
/// The workspace is bound to a descriptor before the write, so the document
/// lands in the tree this command resolved rather than in whatever the workspace
/// path names by the time the member store takes its lock.
pub fn add_member(workspace_path: &Path, filename: &Path, force: bool) -> Result<String> {
    let content = load_text_with_limit(filename, MAX_JSON_DOCUMENT_READ_SIZE, "PublicKey file")?;
    let source_name = format_path_relative_to_cwd(filename);
    let member_handle = build_member_addition_from_content(&content, &source_name)?;
    let workspace_dir = open_workspace_directory(workspace_path)?;

    save_member_content(
        &workspace_dir,
        MemberStatus::Incoming,
        &member_handle,
        &content,
        force,
    )?;

    Ok(member_handle)
}

/// Bind the workspace root a command resolved to the directory it opened.
fn open_workspace_directory(root_path: &Path) -> Result<AnchoredDir> {
    AnchoredDir::open(
        root_path.to_path_buf(),
        DirectoryScope::Generic,
        "workspace root",
    )
}

/// Read what removing one member would cost, holding open what it would remove.
///
/// The scan decides what removing this member would expose, so it is bound to
/// one tree: a workspace path repointed while it runs would otherwise let the
/// operator approve a removal against artifacts they never saw. The document
/// itself is held open for the same reason, because the confirmation prompt sits
/// between this and the write.
pub fn evaluate_member_removal(
    workspace_path: &Path,
    member_handle: &str,
    allow_expired_key: bool,
) -> Result<MemberRemovalReport> {
    let workspace_dir = open_workspace_directory(workspace_path)?;
    let reviewed = review_active_member_document(&workspace_dir, member_handle)?;
    let scan = scan_artifacts_for_member(&workspace_dir, member_handle, allow_expired_key)?;
    Ok(MemberRemovalReport {
        member_handle: member_handle.to_string(),
        affected_artifacts: scan.affected_artifacts,
        warnings: scan.warnings,
        reviewed,
    })
}

struct MemberArtifactScan {
    affected_artifacts: Vec<PathBuf>,
    warnings: Vec<String>,
}

/// Find which artifacts still name the member, warning about the rest.
///
/// An artifact that cannot be read is reported as a warning rather than ending
/// the scan: the operator needs the whole picture before dropping a member. An
/// expired signing key is the exception, because every remaining artifact would
/// fail the same way and the list would be silently empty.
fn scan_artifacts_for_member(
    workspace: &AnchoredDir,
    member_handle: &str,
    allow_expired_key: bool,
) -> Result<MemberArtifactScan> {
    let listing = list_workspace_encrypted_artifacts_at(workspace)?;
    let mut affected_artifacts = Vec::new();
    let mut warnings = listing.warnings;
    for artifact in listing.artifacts {
        match artifact_contains_member(&artifact, member_handle, allow_expired_key) {
            Ok(result) => {
                warnings.extend(result.warnings);
                if result.contains_member {
                    affected_artifacts.push(artifact.path().to_path_buf());
                }
            }
            Err(error) if is_expired_signing_key(&error) => return Err(error),
            Err(error) => warnings.push(format_artifact_warning(artifact.path(), &error)),
        }
    }
    Ok(MemberArtifactScan {
        affected_artifacts,
        warnings,
    })
}

/// The kind is checked alongside the rule because coded operation errors carry
/// rules too, and only a verification failure means the signing key expired.
fn is_expired_signing_key(error: &Error) -> bool {
    error.kind() == ErrorKind::Verify && error.rule() == Some("E_KEY_EXPIRED")
}

/// Remove the member the report was built for.
///
/// The report carries the document the review read, so the write acts on that
/// entry rather than resolving the workspace a second time: between the review
/// and the confirmation the operator answered, both the workspace path and the
/// name under it can be repointed.
pub fn remove_member(report: &MemberRemovalReport) -> Result<MemberRemoveResult> {
    report.reviewed.remove()?;
    Ok(MemberRemoveResult {
        member_handle: report.member_handle.clone(),
    })
}

struct ArtifactMemberScan {
    contains_member: bool,
    warnings: Vec<String>,
}

fn artifact_contains_member(
    artifact: &ArtifactRef,
    member_handle: &str,
    allow_expired_key: bool,
) -> Result<ArtifactMemberScan> {
    debug!(
        "[MEMBER] remove scan: verify artifact path={}",
        format_path_relative_to_cwd(artifact.path())
    );
    let content = load_artifact_content(artifact)?;
    let result = verified_artifact_recipients(&content, allow_expired_key)?;
    let contains_member = result
        .recipients
        .iter()
        .any(|recipient| recipient == member_handle);
    debug!(
        "[MEMBER] remove scan: artifact recipients={} contains_target={}",
        result.recipients.len(),
        contains_member
    );
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
) -> Result<VerifiedArtifactRecipients> {
    if tracing::enabled!(tracing::Level::DEBUG) {
        let artifact_type = match content {
            EncContent::FileEnc(_) => "file",
            EncContent::KvEnc(_) => "kv",
        };
        debug!("[MEMBER] remove scan: detected {artifact_type} artifact");
    }
    let proof = verify_artifact_signature_for_operation(content, allow_expired_key)?;
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
