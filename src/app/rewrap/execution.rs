// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::review::{
    ensure_public_key_snapshot_matches, ensure_text_file_matches_snapshot,
};
use crate::app::trust::approval::{commit_known_key_approvals, ApprovedKnownKey};
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::rewrap::{rewrap_content as rewrap_feature_content, RewrapRequest};
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::format::content::EncryptedContent;
use crate::io::workspace::members::{
    load_active_member_files, promote_snapshotted_incoming_members, IncomingMemberPromotionSnapshot,
};
use crate::support::fs::{atomic, lock};
use crate::Result;
use std::path::Path;

use super::types::{
    RewrapArtifactSnapshot, RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest,
    RewrapFileFailure, RewrapFileSuccess, VerifiedPostPromotionRecipients,
};

pub(crate) fn apply_rewrap_promotions(
    workspace_root: &Path,
    accepted_promotions: &[crate::app::rewrap::types::IncomingPromotionCandidate],
) -> Result<Vec<String>> {
    if accepted_promotions.is_empty() {
        return Ok(Vec::new());
    }
    let snapshots = accepted_promotions
        .iter()
        .map(|candidate| IncomingMemberPromotionSnapshot {
            member_id: candidate.review.member_id.clone(),
            kid: candidate.review.kid.clone(),
            source_path: candidate.source_path.clone(),
            source_content: candidate.source_content.clone(),
        })
        .collect::<Vec<_>>();
    promote_snapshotted_incoming_members(workspace_root, &snapshots)
}

pub(crate) fn execute_confirmed_rewrap_batch(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    expected_post_promotion_members: &[crate::model::public_key::PublicKey],
    execution: ExecutionContext,
    approvals: &[ApprovedKnownKey],
) -> Result<RewrapBatchOutcome> {
    let promoted_member_ids =
        apply_rewrap_promotions(&plan.workspace_root, &request.accepted_promotions)?;
    let actual_post_promotion_members = load_verified_post_promotion_members(
        &plan.workspace_root,
        expected_post_promotion_members,
    )?;
    // Persist approvals before execution: the user's review decision is
    // durable regardless of whether individual artifacts succeed or fail.
    let approval_warnings = if approvals.is_empty() {
        Vec::new()
    } else {
        commit_known_key_approvals(&request.options, &execution, approvals)?.warnings
    };
    let mut outcome =
        execute_rewrap_batch(request, plan, execution, &actual_post_promotion_members)?;
    outcome.promoted_member_ids = promoted_member_ids;
    outcome.warnings = approval_warnings;
    Ok(outcome)
}

/// Execute a batch rewrap over already planned files.
pub(crate) fn execute_rewrap_batch(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    execution: ExecutionContext,
    post_promotion_members: &VerifiedPostPromotionRecipients,
) -> Result<RewrapBatchOutcome> {
    enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
    let mut processed_files = Vec::new();
    let mut failed_files = Vec::new();

    for snapshot in &plan.artifact_snapshots {
        match process_rewrap_file(snapshot, plan, &execution, request, post_promotion_members) {
            Ok(()) => processed_files.push(RewrapFileSuccess {
                output_path: snapshot.file_path.clone(),
            }),
            Err(error) => failed_files.push(RewrapFileFailure {
                output_path: snapshot.file_path.clone(),
                error_message: error.user_message().to_string(),
            }),
        }
    }

    Ok(RewrapBatchOutcome {
        processed_files,
        failed_files,
        promoted_member_ids: Vec::new(),
        warnings: Vec::new(),
    })
}

fn load_verified_post_promotion_members(
    workspace_root: &Path,
    expected: &[crate::model::public_key::PublicKey],
) -> Result<VerifiedPostPromotionRecipients> {
    let actual = load_active_member_files(workspace_root)?;
    ensure_post_promotion_members_match(expected, &actual)?;
    let verified_members = verify_recipient_public_keys(&actual, false)?;
    Ok(VerifiedPostPromotionRecipients::new(verified_members))
}

fn ensure_post_promotion_members_match(
    expected: &[crate::model::public_key::PublicKey],
    actual: &[crate::model::public_key::PublicKey],
) -> Result<()> {
    ensure_public_key_snapshot_matches(
        expected,
        actual,
        "Rewrap post-promotion active members changed and must be reviewed again.",
    )
}

fn process_rewrap_file(
    snapshot: &RewrapArtifactSnapshot,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
    request: &RewrapBatchRequest,
    post_promotion_members: &VerifiedPostPromotionRecipients,
) -> Result<()> {
    let file_path_buf = snapshot.file_path.clone();
    lock::with_file_lock(&file_path_buf, || {
        ensure_rewrap_artifact_matches_snapshot(snapshot)?;
        let content = EncryptedContent::detect(snapshot.content.clone())?;
        let rewrap_request = RewrapRequest {
            member_id: &execution.member_id,
            key_ctx: &execution.key_ctx,
            workspace_root: Some(plan.workspace_root.as_path()),
            target_members: Some(post_promotion_members.verified_members()),
            rotate_key: request.rotate_key,
            clear_disclosure_history: request.clear_disclosure_history,
            debug: request.options.verbose,
        };
        let rewritten = rewrap_feature_content(&content, &rewrap_request)?;

        atomic::save_text(&snapshot.file_path, &rewritten)
    })
}

fn ensure_rewrap_artifact_matches_snapshot(snapshot: &RewrapArtifactSnapshot) -> Result<()> {
    ensure_text_file_matches_snapshot(&snapshot.file_path, Some(&snapshot.content), "Rewrap input")
}

#[cfg(test)]
#[path = "../../../tests/unit/app_rewrap_execution_test.rs"]
mod tests;
