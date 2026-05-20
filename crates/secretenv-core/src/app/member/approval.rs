// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! member verify --approve: verify members and add to known_keys.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::trust::approval::{save_known_key_approvals, ApprovalSaveResult, ApprovedKnownKey};
use crate::app::trust::store::load_or_build_trust_store_for_member;
use crate::app::trust::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
use crate::feature::member::verification::verify_member_public_keys;
use crate::feature::trust::known_keys::{judge_known_key, KnownKeyJudgment};
use crate::io::verify_online::{VerificationStatus, VerifiedGithubIdentity};
use crate::io::workspace::members::load_active_member_files;
use crate::support::runtime::block_on_result;
use crate::{Error, Result};

#[derive(Debug)]
pub struct MemberApprovalEvaluation {
    pub results: Vec<MemberApprovalResult>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct MemberApprovalResult {
    pub member_handle: String,
    pub kid: String,
    pub verified: bool,
    pub approved: bool,
    pub review_required: bool,
    pub already_known: bool,
    pub message: String,
    pub fingerprint: Option<String>,
    pub github_id: Option<u64>,
    pub github_login: Option<String>,
    pub github_binding_configured: bool,
    pub attestor_pub: Option<String>,
    pub verified_github: Option<VerifiedGithubIdentity>,
}

/// Evaluate members for approval (does NOT write trust store).
///
/// `self_member_handle` must be the resolved identity of the current user
/// (from ExecutionContext or equivalent). This ensures evaluate and
/// commit operate on the same trust store.
pub fn evaluate_members_for_approval(
    options: &CommonCommandOptions,
    member_handles: &[String],
    self_member_handle: &str,
) -> Result<MemberApprovalEvaluation> {
    let workspace = require_workspace(options, "member verify --approve")?;

    // Load active members once as the authoritative approval snapshot.
    // This same snapshot is used for both verification and kid resolution,
    // preventing TOCTOU where a file changes between verify and evaluate.
    let active_members = load_active_member_files(&workspace.root_path)?;

    let approval_targets =
        select_approval_targets(&active_members, member_handles, self_member_handle)?;
    let verification_results =
        block_on_result(verify_member_public_keys(&approval_targets, false))?;

    let (_, loaded) = load_or_build_trust_store_for_member(options, self_member_handle)?;
    let protected = loaded.protected;

    let mut results = Vec::new();
    for vr in &verification_results {
        let result = evaluate_candidate_with_snapshot(vr, &active_members, &protected.known_keys)?;
        results.push(result);
    }

    Ok(MemberApprovalEvaluation {
        results,
        warnings: loaded.warnings,
    })
}

/// Persist approved members to the trust store.
///
/// Called after the user has reviewed `evaluate_members_for_approval` results.
pub fn save_member_approvals(
    options: &CommonCommandOptions,
    results: &[MemberApprovalResult],
    execution: &ExecutionContext,
) -> Result<ApprovalSaveResult> {
    let approvals = collect_persistable_approvals(results);
    if approvals.is_empty() {
        return Ok(crate::app::trust::types::TrustMutationResult::new(
            0,
            Vec::new(),
        ));
    }

    save_known_key_approvals(options, execution, &approvals)
}

fn select_approval_targets(
    active_members: &[crate::model::public_key::PublicKey],
    member_handles: &[String],
    self_member_handle: &str,
) -> Result<Vec<crate::model::public_key::PublicKey>> {
    if member_handles.is_empty() {
        return Ok(active_members
            .iter()
            .filter(|pk| pk.protected.subject_handle != self_member_handle)
            .cloned()
            .collect());
    }

    member_handles
        .iter()
        .map(|member_handle| {
            if member_handle == self_member_handle {
                return Err(Error::build_invalid_operation_error(format!(
                    "Self member '{}' must not be approved into known_keys",
                    self_member_handle
                )));
            }
            find_member_public_key(active_members, member_handle)
                .cloned()
                .ok_or_else(|| {
                    Error::build_not_found_error(format!(
                        "Member '{}' not found in active/",
                        member_handle
                    ))
                })
        })
        .collect()
}

/// Evaluate a single candidate using a pre-loaded active members snapshot.
///
/// The `active_members` slice MUST be the same snapshot loaded before
/// `verify_member()` was called, preventing TOCTOU between verification
/// and kid resolution.
fn evaluate_candidate_with_snapshot(
    vr: &crate::io::verify_online::VerificationResult,
    active_members: &[crate::model::public_key::PublicKey],
    known_keys: &[crate::model::trust_store::KnownKey],
) -> Result<MemberApprovalResult> {
    let member_pk = find_member_public_key(active_members, &vr.member_handle);

    let Some(pk) = member_pk else {
        return Ok(MemberApprovalResult {
            member_handle: vr.member_handle.clone(),
            kid: String::new(),
            verified: false,
            approved: false,
            review_required: false,
            already_known: false,
            message: "Member not found in active members".to_string(),
            fingerprint: vr.fingerprint.clone(),
            github_id: vr.verified_github.as_ref().map(|account| account.id),
            github_login: vr
                .verified_github
                .as_ref()
                .map(|account| account.login.clone()),
            github_binding_configured: false,
            attestor_pub: None,
            verified_github: None,
        });
    };
    let candidate = TrustApprovalCandidateBuilder::from_public_key(pk)
        .with_verification_result(vr)
        .build();

    if is_public_key_expired(&pk.protected.expires_at) {
        return Err(Error::build_verification_error(
            "E_KEY_EXPIRED".to_string(),
            format!(
                "PublicKey has expired (expires_at: {}); expired member keys cannot be approved",
                pk.protected.expires_at
            ),
        ));
    }

    // Manual review is only allowed when GitHub binding is absent.
    if vr.status == VerificationStatus::Failed
        || (candidate.github_binding_configured && vr.status != VerificationStatus::Verified)
    {
        return Ok(build_member_approval_result(
            vr, &candidate, false, false, false,
        ));
    }

    let known_key_state = match judge_known_key(known_keys, &candidate.kid, &vr.member_handle) {
        Ok(state) => state,
        Err(e) => {
            return Ok(build_member_approval_result_with_message(
                &candidate,
                true,
                false,
                false,
                format!("Integrity anomaly: {}", e),
            ));
        }
    };

    Ok(build_member_approval_result(
        vr,
        &candidate,
        vr.status == VerificationStatus::Verified,
        matches!(known_key_state, KnownKeyJudgment::New),
        matches!(known_key_state, KnownKeyJudgment::Existing),
    ))
}

fn is_public_key_expired(expires_at: &str) -> bool {
    if expires_at.is_empty() {
        return false;
    }
    matches!(
        check_key_expiry(expires_at, time::OffsetDateTime::now_utc()),
        Ok(KeyExpiryStatus::Expired { .. })
    )
}

fn find_member_public_key<'a>(
    active_members: &'a [crate::model::public_key::PublicKey],
    member_handle: &str,
) -> Option<&'a crate::model::public_key::PublicKey> {
    active_members
        .iter()
        .find(|pk| pk.protected.subject_handle == member_handle)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_member_approval_test.rs"]
mod tests;

fn build_member_approval_result(
    vr: &crate::io::verify_online::VerificationResult,
    candidate: &TrustApprovalCandidate,
    verified: bool,
    review_required: bool,
    already_known: bool,
) -> MemberApprovalResult {
    build_member_approval_result_with_message(
        candidate,
        verified,
        review_required,
        already_known,
        vr.message.clone(),
    )
}

fn build_member_approval_result_with_message(
    candidate: &TrustApprovalCandidate,
    verified: bool,
    review_required: bool,
    already_known: bool,
    message: String,
) -> MemberApprovalResult {
    MemberApprovalResult {
        member_handle: candidate.member_handle.to_string(),
        kid: candidate.kid.to_string(),
        verified,
        approved: false,
        review_required,
        already_known,
        message,
        fingerprint: candidate.fingerprint.clone(),
        github_id: candidate.github_id,
        github_login: candidate.github_login.clone(),
        github_binding_configured: candidate.github_binding_configured,
        attestor_pub: candidate.attestor_pub.clone(),
        verified_github: candidate.verified_github.clone(),
    }
}

fn collect_persistable_approvals(results: &[MemberApprovalResult]) -> Vec<ApprovedKnownKey> {
    results
        .iter()
        .filter(|result| result.approved)
        .map(build_approved_known_key)
        .collect()
}

fn build_approved_known_key(result: &MemberApprovalResult) -> ApprovedKnownKey {
    ApprovedKnownKey::from_review(
        &result.member_handle,
        &result.kid,
        result.attestor_pub.clone(),
        result.verified_github.as_ref(),
    )
}

impl From<&MemberApprovalResult> for TrustApprovalCandidate {
    fn from(result: &MemberApprovalResult) -> Self {
        TrustApprovalCandidateBuilder::new(&result.member_handle, &result.kid)
            .with_fingerprint(result.fingerprint.clone())
            .with_attestor_pub(result.attestor_pub.clone())
            .with_verified_github(result.verified_github.clone())
            .with_github_review_fields(result.github_id, result.github_login.clone())
            .with_github_binding_configured(result.github_binding_configured)
            .with_online_verification_context(
                result.github_binding_configured,
                Some(result.message.clone()),
            )
            .build()
    }
}
