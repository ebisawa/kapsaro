// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! member verify --approve: verify members and add to known_keys.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::trust::approval::{
    commit_known_key_approvals, ApprovalSaveResult, ApprovedKnownKey,
};
use crate::app::trust::store::load_or_build_trust_store_for_member;
use crate::app::trust::TrustApprovalCandidate;
use crate::feature::member::verification::verify_member_public_keys;
use crate::feature::trust::known_keys::{assess_known_key, KnownKeyAssessment};
use crate::io::verify_online::{VerificationStatus, VerifiedGithubIdentity};
use crate::io::workspace::members::load_active_member_files;
use crate::model::identity::{Kid, MemberId};
use crate::support::runtime::block_on_result;
use crate::{Error, Result};

#[derive(Debug)]
pub struct MemberApprovalEvaluation {
    pub results: Vec<MemberApprovalResult>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct MemberApprovalResult {
    pub member_id: String,
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
/// `self_member_id` must be the resolved identity of the current user
/// (from ExecutionContext or equivalent). This ensures evaluate and
/// commit operate on the same trust store.
pub fn evaluate_members_for_approval(
    options: &CommonCommandOptions,
    member_ids: &[String],
    self_member_id: &str,
) -> Result<MemberApprovalEvaluation> {
    let workspace = require_workspace(options, "member verify --approve")?;

    // Load active members ONCE as the authoritative snapshot (spec §6.2).
    // This same snapshot is used for both verification and kid resolution,
    // preventing TOCTOU where a file changes between verify and evaluate.
    let active_members = load_active_member_files(&workspace.root_path)?;

    let approval_targets = select_approval_targets(&active_members, member_ids, self_member_id)?;
    let verification_results =
        block_on_result(verify_member_public_keys(&approval_targets, false))?;

    let (_, loaded) = load_or_build_trust_store_for_member(options, self_member_id)?;
    let protected = loaded.protected;

    let mut results = Vec::new();
    for vr in &verification_results {
        let result = evaluate_candidate_with_snapshot(vr, &active_members, &protected.known_keys);
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
pub fn commit_approvals(
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

    commit_known_key_approvals(options, execution, &approvals)
}

fn select_approval_targets(
    active_members: &[crate::model::public_key::PublicKey],
    member_ids: &[String],
    self_member_id: &str,
) -> Result<Vec<crate::model::public_key::PublicKey>> {
    if member_ids.is_empty() {
        return Ok(active_members
            .iter()
            .filter(|pk| pk.protected.member_id != self_member_id)
            .cloned()
            .collect());
    }

    member_ids
        .iter()
        .map(|member_id| {
            if member_id == self_member_id {
                return Err(Error::InvalidOperation {
                    message: format!(
                        "Self member '{}' must not be approved into known_keys",
                        self_member_id
                    ),
                });
            }
            find_member_public_key(active_members, member_id)
                .cloned()
                .ok_or_else(|| Error::NotFound {
                    message: format!("Member '{}' not found in active/", member_id),
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
) -> MemberApprovalResult {
    let member_pk = find_member_public_key(active_members, &vr.member_id);
    let fingerprint = vr.fingerprint.clone();
    let (github_id, github_login) = extract_github_info(vr);

    let Some(pk) = member_pk else {
        return MemberApprovalResult {
            member_id: vr.member_id.clone(),
            kid: String::new(),
            verified: false,
            approved: false,
            review_required: false,
            already_known: false,
            message: "Member not found in active members".to_string(),
            fingerprint,
            github_id,
            github_login,
            github_binding_configured: false,
            attestor_pub: None,
            verified_github: None,
        };
    };
    let kid = pk.protected.kid.clone();
    let attestor_pub = pk.protected.identity.attestation.pub_.clone();
    let github_binding_configured = pk
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref())
        .is_some();

    // Spec §14.1: manual review is only allowed when GitHub binding is absent.
    if vr.status == VerificationStatus::Failed
        || (github_binding_configured && vr.status != VerificationStatus::Verified)
    {
        return build_not_verified_result(vr, &kid, github_binding_configured);
    }

    let known_key_state = match assess_known_key(known_keys, &kid, &vr.member_id) {
        Ok(state) => state,
        Err(e) => {
            return MemberApprovalResult {
                member_id: vr.member_id.clone(),
                kid,
                verified: true,
                approved: false,
                review_required: false,
                already_known: false,
                message: format!("Integrity anomaly: {}", e),
                fingerprint,
                github_id,
                github_login,
                github_binding_configured,
                attestor_pub: Some(attestor_pub),
                verified_github: vr.verified_github.clone(),
            };
        }
    };

    MemberApprovalResult {
        member_id: vr.member_id.clone(),
        kid,
        verified: vr.status == VerificationStatus::Verified,
        approved: false,
        review_required: matches!(known_key_state, KnownKeyAssessment::New),
        already_known: matches!(known_key_state, KnownKeyAssessment::Existing),
        message: vr.message.clone(),
        fingerprint,
        github_id,
        github_login,
        github_binding_configured,
        attestor_pub: Some(attestor_pub),
        verified_github: vr.verified_github.clone(),
    }
}

fn find_member_public_key<'a>(
    active_members: &'a [crate::model::public_key::PublicKey],
    member_id: &str,
) -> Option<&'a crate::model::public_key::PublicKey> {
    active_members
        .iter()
        .find(|pk| pk.protected.member_id == member_id)
}

#[cfg(test)]
#[path = "../../../tests/unit/app_member_approval_test.rs"]
mod tests;

fn extract_github_info(
    vr: &crate::io::verify_online::VerificationResult,
) -> (Option<u64>, Option<String>) {
    let github = vr.verified_github.as_ref();
    (github.map(|g| g.id), github.map(|g| g.login.clone()))
}

fn build_not_verified_result(
    vr: &crate::io::verify_online::VerificationResult,
    kid: &str,
    github_binding_configured: bool,
) -> MemberApprovalResult {
    let (github_id, github_login) = extract_github_info(vr);
    MemberApprovalResult {
        member_id: vr.member_id.clone(),
        kid: kid.to_string(),
        verified: false,
        approved: false,
        review_required: false,
        already_known: false,
        message: vr.message.clone(),
        fingerprint: vr.fingerprint.clone(),
        github_id,
        github_login,
        github_binding_configured,
        attestor_pub: None,
        verified_github: vr.verified_github.clone(),
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
        &result.member_id,
        &result.kid,
        result.attestor_pub.clone(),
        result.verified_github.as_ref(),
    )
}

impl From<&MemberApprovalResult> for TrustApprovalCandidate {
    fn from(result: &MemberApprovalResult) -> Self {
        TrustApprovalCandidate {
            member_id: MemberId::try_from(result.member_id.clone())
                .expect("approved member_id must be valid"),
            kid: Kid::try_from(result.kid.clone()).expect("approved kid must be valid"),
            fingerprint: result.fingerprint.clone(),
            github_id: result.github_id,
            github_login: result.github_login.clone(),
            attestor_pub: result.attestor_pub.clone(),
            verified_github: result.verified_github.clone(),
            github_binding_configured: result.github_binding_configured,
            online_verification_attempted: result.github_binding_configured,
            online_verification_message: Some(result.message.clone()),
            public_key: None,
            requires_out_of_band_verification: true,
        }
    }
}
