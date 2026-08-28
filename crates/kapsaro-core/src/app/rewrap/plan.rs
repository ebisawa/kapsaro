// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap planning.
//! Works out which artifacts and recipients a key rotation has to touch.

use crate::app::artifact::{list_workspace_encrypted_artifacts_at, ArtifactRef};
use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::trust::load_read_trust_context;
use crate::app::trust::TrustApprovalCandidateBuilder;
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, WORKSPACE_INCOMING_MEMBER_CONTEXT,
};
use crate::io::workspace::members::{
    capture_promotion_destination_at, ensure_workspace_member_kid_uniqueness,
    open_member_documents_at, MemberStatus, PromotionDestinationState,
};
use crate::model::public_key::PublicKey;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_dir_identity, DirectoryFd};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use super::types::{
    IncomingPromotionCandidate, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport, RewrapBatchPlan,
};

/// Resolve workspace inputs, incoming promotion candidates, and target files.
pub fn build_rewrap_batch_plan(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    explicit_targets: &[PathBuf],
) -> Result<RewrapBatchPlan> {
    let workspace = require_workspace(options, "rewrap")?;
    ensure_workspace_member_kid_uniqueness(&workspace.root_path)?;
    let workspace_dir = execution.fixed_workspace_directory()?;
    let incoming_index = load_incoming_index(workspace_dir)?;
    let targets = collect_rewrap_targets(workspace_dir, explicit_targets)?;
    let pre_promotion_trust = load_read_trust_context(options, execution, "rewrap")?.trust_ctx;
    let incoming_report = build_incoming_report(&incoming_index)?;
    if targets.artifacts.is_empty() {
        return Err(build_no_rewrap_target_error(&targets.warnings));
    }

    Ok(RewrapBatchPlan {
        pre_promotion_trust,
        incoming_report,
        artifacts: targets.artifacts,
        discovery_warnings: targets.warnings,
    })
}

/// Report that nothing was found, naming the entries the search had to skip.
///
/// A secrets directory whose entries could not all be inspected can look empty
/// for a reason the operator can fix, so the skipped entries travel with the
/// failure instead of being dropped with the empty list.
fn build_no_rewrap_target_error(warnings: &[String]) -> Error {
    let mut message = String::from(
        "No encrypted files found for rewrap.\n\
         Searched: workspace secrets/",
    );
    for warning in warnings {
        message.push('\n');
        message.push_str(warning);
    }
    message.push_str("\nAction: Pass --target <path> for an explicit file.");
    Error::build_not_found_error(message)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_rewrap_plan_test.rs"]
mod tests;

/// The artifacts one rewrap run acts on, and what its search had to skip.
struct RewrapTargets {
    artifacts: Vec<ArtifactRef>,
    warnings: Vec<String>,
}

/// Resolve the artifacts to rewrap, from explicit targets or from the workspace.
///
/// The search reads through the descriptor this command bound to, so the set of
/// artifacts it rewrites comes from the tree it started in. Explicit targets
/// name what the operator already chose, so nothing is searched and nothing can
/// be skipped; each is bound to its own directory the same way.
fn collect_rewrap_targets(
    workspace: &AnchoredDir,
    explicit_targets: &[PathBuf],
) -> Result<RewrapTargets> {
    let (candidates, warnings) = if explicit_targets.is_empty() {
        let listing = list_workspace_encrypted_artifacts_at(workspace)?;
        (listing.artifacts, listing.warnings)
    } else {
        (open_explicit_rewrap_targets(explicit_targets)?, Vec::new())
    };
    Ok(RewrapTargets {
        artifacts: dedupe_rewrap_targets(candidates)?,
        warnings,
    })
}

fn open_explicit_rewrap_targets(explicit_targets: &[PathBuf]) -> Result<Vec<ArtifactRef>> {
    explicit_targets
        .iter()
        .map(|path| ArtifactRef::open_from_path(path.as_path()))
        .collect()
}

/// Keep one entry per directory-and-name, in the order the targets arrived.
///
/// Two spellings of the same entry are one target. Two entries that merely
/// share an inode are not: the replacement is published by rename, which breaks
/// the link, so folding hardlinked names together would leave the second one
/// still holding the content nobody rewrapped.
fn dedupe_rewrap_targets(candidates: Vec<ArtifactRef>) -> Result<Vec<ArtifactRef>> {
    let mut seen = BTreeSet::new();
    let mut kept = Vec::new();
    for artifact in candidates {
        let directory = open_dir_identity(artifact.directory().as_ref())?;
        if seen.insert((directory, artifact.name().to_string())) {
            kept.push(artifact);
        }
    }
    Ok(kept)
}

fn build_incoming_report(
    incoming_index: &BTreeMap<String, IncomingSnapshot>,
) -> Result<Option<IncomingVerificationReport>> {
    if incoming_index.is_empty() {
        return Ok(None);
    }

    let mut report = IncomingVerificationReport::default();
    for snapshot in incoming_index.values() {
        let candidate = build_incoming_candidate(snapshot)?;
        match candidate.review.category {
            IncomingVerificationCategory::BindingConfigured => {
                report.binding_configured.push(candidate);
            }
            IncomingVerificationCategory::Failed => report.failed.push(candidate),
            IncomingVerificationCategory::NotConfigured => report.not_configured.push(candidate),
            IncomingVerificationCategory::Verified => unreachable!(),
        }
    }

    Ok(Some(report))
}

fn build_incoming_candidate(snapshot: &IncomingSnapshot) -> Result<IncomingPromotionCandidate> {
    let review = match verify_public_key_for_verification_context(
        &snapshot.public_key,
        WORKSPACE_INCOMING_MEMBER_CONTEXT,
    ) {
        Ok(_) => build_pending_review(snapshot),
        Err(error) => IncomingVerificationItem {
            member_handle: snapshot.public_key.protected.subject_handle.clone(),
            kid: snapshot.public_key.protected.kid.clone(),
            category: IncomingVerificationCategory::Failed,
            message: format!(
                "Offline verification failed: {}",
                error.format_user_message()
            ),
            fingerprint: None,
            verified_github: None,
            github_binding_configured: github_binding_configured(&snapshot.public_key),
            attestor_pub: None,
        },
    };

    Ok(IncomingPromotionCandidate {
        review,
        source_content: snapshot.source_content.clone(),
        destination: snapshot.destination.clone(),
        public_key: snapshot.public_key.clone(),
    })
}

fn build_pending_review(snapshot: &IncomingSnapshot) -> IncomingVerificationItem {
    let candidate = TrustApprovalCandidateBuilder::from_public_key(&snapshot.public_key).build();
    let (category, message) = build_pending_review_category(candidate.github_binding_configured);

    IncomingVerificationItem {
        member_handle: snapshot.public_key.protected.subject_handle.clone(),
        kid: snapshot.public_key.protected.kid.clone(),
        category,
        message,
        fingerprint: candidate.fingerprint,
        verified_github: None,
        github_binding_configured: candidate.github_binding_configured,
        attestor_pub: candidate.attestor_pub,
    }
}

fn github_binding_configured(public_key: &PublicKey) -> bool {
    public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some()
}

fn build_pending_review_category(
    binding_configured: bool,
) -> (IncomingVerificationCategory, String) {
    if binding_configured {
        (
            IncomingVerificationCategory::BindingConfigured,
            "GitHub binding configured; online verification will run if trust update is required"
                .to_string(),
        )
    } else {
        (
            IncomingVerificationCategory::NotConfigured,
            "No binding_claims.github_account configured".to_string(),
        )
    }
}

#[derive(Debug, Clone)]
struct IncomingSnapshot {
    source_content: String,
    destination: PromotionDestinationState,
    public_key: PublicKey,
}

/// Read every incoming document together with the active document it would
/// replace, so both sides of a promotion are reviewed as one state.
///
/// Both sides are read through the workspace descriptor the command bound to,
/// which is the descriptor the promotion later checks its snapshots against.
///
/// Each incoming document is read once, and the bytes kept for the promotion are
/// the bytes that were verified and shown to the operator. Reading the name a
/// second time to get them would put a window between the review and the capture
/// in which the document could be replaced, and the promotion's own check only
/// compares against what that second read returned.
fn load_incoming_index<D>(workspace: &D) -> Result<BTreeMap<String, IncomingSnapshot>>
where
    D: DirectoryFd,
{
    let documents = open_member_documents_at(workspace, MemberStatus::Incoming)?;
    let mut index = BTreeMap::new();
    for name in documents.names() {
        let document = documents.load_verified_document(name)?;
        let member_handle = document.public_key.protected.subject_handle.clone();
        let destination = capture_promotion_destination_at(workspace, &member_handle)?;
        index.insert(
            member_handle,
            IncomingSnapshot {
                source_content: document.content,
                destination,
                public_key: document.public_key,
            },
        );
    }
    Ok(index)
}
