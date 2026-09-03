// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! member verify --approve: verify members and add to known_keys.

use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
use crate::feature::member::verification::{
    append_verification_warnings, build_offline_verification_failure, has_github_claim,
    verify_member_public_key,
};
use crate::feature::trust::known_keys::{judge_known_key, KnownKeyJudgment};
use crate::io::verify_online::{VerificationResult, VerificationStatus, VerifiedGithubIdentity};
use crate::io::workspace::members::load_active_member_files_at;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::service::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::service::trust::store::{load_session_trust_store, trust_store_or_empty};
use crate::service::trust::TrustCommandSession;
use crate::service::trust::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryScope;
use crate::support::runtime::block_on_result;
use crate::{Error, Result};
use std::collections::BTreeMap;
use tracing::debug;

/// Fixed workspace and local trust capabilities for one member approval flow.
pub struct MemberApprovalSession {
    workspace: AnchoredDir,
    trust: TrustCommandSession,
}

impl MemberApprovalSession {
    /// Bind an explicit workspace to the already selected local signing identity.
    pub fn open(
        workspace_path: impl AsRef<std::path::Path>,
        trust: TrustCommandSession,
    ) -> Result<Self> {
        let workspace = AnchoredDir::open(
            workspace_path.as_ref().to_path_buf(),
            DirectoryScope::Generic,
            "workspace root",
        )?;
        Ok(Self { workspace, trust })
    }

    /// Return the fixed trust capability used for recovery and persistence.
    pub fn trust_command(&self) -> &TrustCommandSession {
        &self.trust
    }
}

#[derive(Debug)]
pub struct MemberApprovalEvaluation {
    pub results: Vec<MemberApprovalResult>,
    approvals: BTreeMap<Kid, ApprovedKnownKey>,
    active_members: Vec<PublicKey>,
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

#[cfg(test)]
impl MemberApprovalEvaluation {
    pub(crate) fn for_test(
        results: Vec<MemberApprovalResult>,
        active_members: &[PublicKey],
    ) -> Result<Self> {
        let mut approvals = BTreeMap::new();
        for result in results.iter().filter(|result| result.approved) {
            let public_key = find_member_public_key(active_members, &result.member_handle)
                .ok_or_else(|| Error::build_not_found_error("test member missing".to_string()))?;
            let candidate = build_test_candidate(public_key, result)?;
            let approval = ApprovedKnownKey::from_candidate(&candidate)?;
            approvals.insert(approval.kid().clone(), approval);
        }
        Ok(Self {
            results,
            approvals,
            active_members: active_members.to_vec(),
        })
    }
}

#[cfg(test)]
fn build_test_candidate(
    public_key: &PublicKey,
    result: &MemberApprovalResult,
) -> Result<TrustApprovalCandidate> {
    let verified = crate::feature::verify::public_key::verify_public_key_for_verification_context(
        public_key,
        crate::feature::verify::public_key::WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
    )?;
    let Some(github) = result.verified_github.as_ref() else {
        return TrustApprovalCandidateBuilder::from_verified_signing_public_key(
            &verified.verified_public_key,
        )
        .map(TrustApprovalCandidateBuilder::build);
    };
    let candidate = crate::service::trust::KnownKeyReviewCandidate::for_test_with_github_account_id(
        &public_key.protected.subject_handle,
        &public_key.protected.kid,
        &public_key.protected.attestation.pub_,
        Some(github.id),
        result.fingerprint.clone(),
    );
    let evidence = crate::service::online::VerifiedGitHubEvidence::for_test(
        &candidate,
        github.id,
        github.login.clone(),
        github.fingerprint.clone(),
        github.matched_key_id,
    );
    Ok(
        TrustApprovalCandidateBuilder::from_known_key_candidate(&candidate)
            .with_verified_service_evidence(evidence)
            .build(),
    )
}

/// Evaluate members for approval (does NOT write trust store).
///
/// Every identity is taken from `session`, so the store read here is the one
/// `save_member_approvals` later commits to.
pub fn evaluate_members_for_approval(
    session: &MemberApprovalSession,
    member_handles: &[String],
) -> Result<MemberApprovalEvaluation> {
    let workspace = &session.workspace;

    // Load active members once as the authoritative approval snapshot.
    // This same snapshot is used for both verification and kid resolution,
    // preventing TOCTOU where a file changes between verify and evaluate.
    // The read goes through the descriptor this command bound to, so a
    // workspace repointed while it runs cannot substitute another tree.
    let active_members = load_active_member_files_at(workspace)?;

    let owner = session.trust.owner().clone();
    let verification_results = verify_approval_targets(&active_members, member_handles, &owner)?;

    let loaded = load_session_trust_store(&session.trust)?;
    let known_keys = trust_store_or_empty(&owner, loaded)?.protected.known_keys;

    let evaluated = verification_results
        .iter()
        .map(|vr| evaluate_candidate_with_snapshot(vr, &active_members, &known_keys))
        .collect::<Result<Vec<_>>>()?;
    let mut approvals = BTreeMap::new();
    let mut results = Vec::with_capacity(evaluated.len());
    for (result, approval) in evaluated {
        if let Some(approval) = approval {
            approvals.insert(approval.kid().clone(), approval);
        }
        results.push(result);
    }
    Ok(MemberApprovalEvaluation {
        results,
        approvals,
        active_members,
    })
}

/// Verify the public keys of the members this approval run targets.
fn verify_approval_targets(
    active_members: &[PublicKey],
    member_handles: &[String],
    owner: &MemberHandle,
) -> Result<Vec<VerificationResult>> {
    verify_approval_targets_with_verifier(active_members, member_handles, owner, |public_key| {
        let mut results = block_on_result(super::verification::verify_member_public_keys(
            std::slice::from_ref(public_key),
        ))?;
        results.pop().ok_or_else(|| {
            Error::build_invalid_operation_error(
                "GitHub verification returned no member result".to_string(),
            )
        })
    })
}

fn verify_approval_targets_with_verifier<VerifyOnline>(
    active_members: &[PublicKey],
    member_handles: &[String],
    owner: &MemberHandle,
    mut verify_online: VerifyOnline,
) -> Result<Vec<VerificationResult>>
where
    VerifyOnline: FnMut(&PublicKey) -> Result<VerificationResult>,
{
    let approval_targets = select_approval_targets(active_members, member_handles, owner.as_str())?;
    debug!(
        "[MEMBER] approve: verify candidate public keys active_count={}, target_count={}",
        active_members.len(),
        approval_targets.len()
    );
    approval_targets
        .iter()
        .map(|public_key| {
            if has_github_claim(public_key) {
                verify_online(public_key)
            } else {
                Ok(verify_unbound_approval_target(public_key))
            }
        })
        .collect()
}

fn verify_unbound_approval_target(public_key: &PublicKey) -> VerificationResult {
    let subject = match verify_member_public_key(public_key) {
        Ok(subject) => subject,
        Err(error) => {
            return build_offline_verification_failure(
                &public_key.protected.subject_handle,
                error,
                false,
            )
        }
    };
    let fingerprint = crate::io::ssh::protocol::build_sha256_fingerprint(
        &subject.public_key.protected.attestation.pub_,
    )
    .ok();
    append_verification_warnings(
        VerificationResult::not_configured(
            &subject.member_handle,
            "No binding_claims.github_account configured",
            fingerprint,
            false,
        ),
        &subject.warnings,
    )
}

/// Persist approved members to the trust store.
///
/// Called after the user has reviewed `evaluate_members_for_approval` results.
pub fn save_member_approvals(
    session: &MemberApprovalSession,
    evaluation: &MemberApprovalEvaluation,
) -> Result<usize> {
    let approvals = collect_persistable_approvals(evaluation)?;
    if approvals.is_empty() {
        return Ok(0);
    }

    let current_members = load_active_member_files_at(&session.workspace)?;
    if current_members != evaluation.active_members {
        return Err(Error::build_verification_error(
            "E_TRUST_TARGET_CHANGED",
            "Workspace members changed during approval. Run the command again.".to_string(),
        ));
    }

    save_known_key_approvals(&session.trust, &approvals)
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
/// `verify_member_public_keys()` was called, preventing TOCTOU between verification
/// and kid resolution.
fn evaluate_candidate_with_snapshot(
    vr: &crate::io::verify_online::VerificationResult,
    active_members: &[crate::model::public_key::PublicKey],
    known_keys: &[crate::model::trust_store::KnownKey],
) -> Result<(MemberApprovalResult, Option<ApprovedKnownKey>)> {
    let member_pk = find_member_public_key(active_members, &vr.member_handle);

    let Some(pk) = member_pk else {
        return Ok((build_missing_active_member_approval_result(vr), None));
    };
    let verified = crate::feature::verify::public_key::verify_public_key_for_verification_context(
        pk,
        crate::feature::verify::public_key::WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT,
    )?;
    let builder = TrustApprovalCandidateBuilder::from_verified_signing_public_key(
        &verified.verified_public_key,
    )?
    .with_verification_result(vr);
    let service_candidate = builder.build().service_candidate().clone();
    let verified_service_evidence = (vr.status == VerificationStatus::Verified)
        .then(|| {
            crate::service::online::VerifiedGitHubEvidence::from_result(
                &service_candidate,
                vr.clone(),
            )
        })
        .transpose()?;
    let candidate = TrustApprovalCandidateBuilder::from_known_key_candidate(&service_candidate)
        .with_verification_result(vr)
        .with_optional_verified_service_evidence(verified_service_evidence)
        .build();

    enforce_candidate_public_key_active(&pk.protected.expires_at)?;

    if !evaluate_candidate_online_verification(vr, &candidate) {
        return Ok((
            build_member_approval_result(vr, &candidate, false, false, false),
            None,
        ));
    }

    let result = evaluate_candidate_known_key_state(vr, &candidate, known_keys)?;
    let approval = result
        .review_required
        .then(|| ApprovedKnownKey::from_candidate(&candidate))
        .transpose()?;
    Ok((result, approval))
}

fn enforce_candidate_public_key_active(expires_at: &str) -> Result<()> {
    if !is_public_key_expired(expires_at) {
        return Ok(());
    }
    Err(Error::build_verification_error(
        "E_KEY_EXPIRED".to_string(),
        format!(
            "PublicKey has expired.\n\
             Expires at: {}\n\
             Rotate the member key before approval.",
            expires_at
        ),
    ))
}

fn evaluate_candidate_online_verification(
    vr: &crate::io::verify_online::VerificationResult,
    candidate: &TrustApprovalCandidate,
) -> bool {
    // Manual review is only allowed when GitHub binding is absent.
    vr.status != VerificationStatus::Failed
        && (!candidate.github_binding_configured() || vr.status == VerificationStatus::Verified)
}

fn evaluate_candidate_known_key_state(
    vr: &crate::io::verify_online::VerificationResult,
    candidate: &TrustApprovalCandidate,
    known_keys: &[crate::model::trust_store::KnownKey],
) -> Result<MemberApprovalResult> {
    let known_key_state = match judge_known_key(known_keys, candidate.kid(), &vr.member_handle) {
        Ok(state) => state,
        Err(e) => {
            return Ok(build_member_approval_result_with_message(
                candidate,
                true,
                false,
                false,
                format!("Integrity anomaly: {}", e),
            ));
        }
    };

    Ok(build_member_approval_result(
        vr,
        candidate,
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

fn build_missing_active_member_approval_result(
    vr: &crate::io::verify_online::VerificationResult,
) -> MemberApprovalResult {
    MemberApprovalResult {
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
    }
}

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
        member_handle: candidate.member_handle().to_string(),
        kid: candidate.kid().to_string(),
        verified,
        approved: false,
        review_required,
        already_known,
        message,
        fingerprint: candidate.fingerprint().map(str::to_string),
        github_id: candidate.github_id(),
        github_login: candidate.github_login().map(str::to_string),
        github_binding_configured: candidate.github_binding_configured(),
        attestor_pub: Some(candidate.attestor_pub().to_string()),
        verified_github: candidate.verified_service_evidence().map(|evidence| {
            VerifiedGithubIdentity::new(
                evidence.account().id(),
                evidence.account().login().to_string(),
                evidence.fingerprint().to_string(),
                evidence.matched_key_id(),
            )
        }),
    }
}

fn collect_persistable_approvals(
    evaluation: &MemberApprovalEvaluation,
) -> Result<Vec<ApprovedKnownKey>> {
    evaluation
        .results
        .iter()
        .filter(|result| result.approved)
        .map(|result| {
            let kid = Kid::new(result.kid.clone())?;
            evaluation.approvals.get(&kid).cloned().ok_or_else(|| {
                Error::build_invalid_operation_error(
                    "Approved member result has no verified approval capability".to_string(),
                )
            })
        })
        .collect()
}
