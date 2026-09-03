// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust store approval persistence.

use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::model::identity::{Kid, MemberHandle};
use crate::service::diagnostics::restore_local_state_warnings;
use crate::service::trust::store::load_verified_local_trust_store;
use crate::service::trust::TrustApprovalCandidate;
use crate::service::trust::TrustCommandSession;
use crate::service::trust::{
    ApprovalConflictHandling, KnownKeyApprovalEvidence, LocalTrustStore, TrustApproval,
    TrustApprovalOutcome, VerifiedLocalTrustStoreLoadResult,
};
use crate::Result;

#[derive(Debug, Clone, PartialEq)]
pub struct ApprovedKnownKey {
    member_handle: MemberHandle,
    kid: Kid,
    approval: TrustApproval,
}

impl ApprovedKnownKey {
    pub(crate) fn kid(&self) -> &Kid {
        &self.kid
    }

    pub(crate) fn from_candidate(candidate: &TrustApprovalCandidate) -> Result<Self> {
        let service_candidate = candidate.service_candidate();
        let mut evidence = KnownKeyApprovalEvidence::none()
            .with_ssh_attestor_public_key(service_candidate.ssh_attestor_public_key());
        if let Some(verified) = candidate.verified_service_evidence().cloned() {
            evidence = evidence.with_verified_github_account(verified);
        }
        Ok(Self {
            member_handle: service_candidate.subject_handle().clone(),
            kid: service_candidate.kid().clone(),
            approval: TrustApproval::known_key(service_candidate, evidence)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        member_handle: &str,
        kid: &str,
        attestor_pub: Option<String>,
        verified_github: Option<&crate::io::verify_online::VerifiedGithubIdentity>,
    ) -> Self {
        let member_handle = MemberHandle::new(member_handle).expect("valid test member handle");
        let kid = Kid::new(kid).expect("canonical test kid");
        let github = verified_github.map(|verified| {
            (
                verified.id,
                verified.login.clone(),
                verified.fingerprint.clone(),
                verified.matched_key_id,
            )
        });
        let approval = TrustApproval::known_key_with_evidence_for_test(
            member_handle.as_str(),
            kid.as_str(),
            attestor_pub,
            github,
        );
        Self {
            member_handle,
            kid,
            approval,
        }
    }
}

impl From<&ApprovedKnownKey> for KnownKeyIdentity {
    fn from(value: &ApprovedKnownKey) -> Self {
        Self::new(value.member_handle.clone(), value.kid.clone())
    }
}

/// Store the key approvals an operator just agreed to.
///
/// Every caller reaches here after showing the operator what it was about to
/// approve, and two runs approving different keys must each keep what they
/// approved, so the write merges into the latest stored content rather than
/// binding itself to the bytes the observation saw.
pub fn save_known_key_approvals(
    session: &TrustCommandSession,
    approvals: &[ApprovedKnownKey],
) -> Result<usize> {
    if approvals.is_empty() {
        return Ok(0);
    }

    let trust_dir = session.ensured_trust_directory()?;
    LocalTrustStore::open_from_anchored_base(session.home(), session.owner().clone())
        .apply_approvals_with_conflict_handling_at(
            trust_dir.as_ref(),
            approvals
                .iter()
                .map(|approval| approval.approval.clone())
                .collect(),
            session.key_ctx(),
            ApprovalConflictHandling::merge(),
        )
        .map(complete_approval)
}

/// Observe the trust store one recipient-set review will be decided against.
///
/// Approving a recipient set replaces the whole record its sid names rather
/// than adding one beside it, so merging has no ground here. The operator
/// decides on the strength of the store as it stood when they were asked, and
/// a run that replaced the record for that sid while they were deciding left
/// one they never saw: writing the reviewed set over it would put back a
/// recipient that run dropped. Observing before the prompt is what makes the
/// commit refuse that, so the operator reviews the artifact again instead.
///
/// `CreateIfMissing` means this observation creates the trust directory when
/// it is absent, and this call runs before the operator has confirmed
/// anything. Declining the approval afterward therefore still leaves an empty
/// trust directory behind; before this moved to observing ahead of the
/// prompt, the directory was only created once the operator had confirmed.
/// The trust-approval facade documents an empty directory left behind this
/// way as harmless, so this is recorded here as the move that introduced this
/// particular path to it rather than as a new case to guard against.
pub(crate) fn observe_recipient_set_approval_store(
    session: &TrustCommandSession,
) -> Result<Option<VerifiedLocalTrustStoreLoadResult>> {
    let trust_dir = session.ensured_trust_directory()?;
    load_verified_local_trust_store(
        session.home(),
        Some(trust_dir.as_ref()),
        session.owner().clone(),
        Some(session.keystore()),
    )
}

/// Store the recipient-set approval an operator just agreed to.
///
/// `observed` is the store the decision was made against, and the commit
/// accepts nothing else.
pub(crate) fn save_reviewed_recipient_set_approval(
    session: &TrustCommandSession,
    observed: Option<&VerifiedLocalTrustStoreLoadResult>,
    approval: ArtifactRecipientSet,
) -> Result<usize> {
    let trust_dir = session.ensured_trust_directory()?;
    let store = LocalTrustStore::open_from_anchored_base(session.home(), session.owner().clone());
    let conflict = observed.map_or_else(
        ApprovalConflictHandling::surface_absent,
        ApprovalConflictHandling::surface,
    );
    store
        .apply_approvals_with_conflict_handling_at(
            trust_dir.as_ref(),
            vec![TrustApproval::recipient_set_from_artifact(&approval)?],
            session.key_ctx(),
            conflict,
        )
        .map(complete_approval)
}

fn complete_approval(outcome: TrustApprovalOutcome) -> usize {
    let (applied, warnings) = outcome.into_parts();
    restore_local_state_warnings(warnings);
    applied
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_approval_test.rs"]
mod tests;
