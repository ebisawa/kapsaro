// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust store approval persistence.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::{
    execute_trust_store_mutation_with_execution, execute_trust_store_mutation_with_preparation,
    observe_execution_trust_store, TrustStoreWriteBinding,
};
use crate::app::trust::TrustApprovalCandidate;
use crate::feature::trust::known_keys::add_known_key;
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::feature::trust::recipient_sets::{upsert_recipient_set, ArtifactRecipientSet};
use crate::feature::trust::store_mutation::{TrustStoreMutation, TrustStoreMutationMode};
use crate::feature::trust::transaction::ObservedTrustStore;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount, TrustStoreProtected,
};
use crate::support::time::generate_current_timestamp;
use crate::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedKnownKey {
    member_handle: MemberHandle,
    kid: Kid,
    github_id: Option<u64>,
    github_login: Option<String>,
    attestor_pub: Option<String>,
}

impl ApprovedKnownKey {
    pub fn from_review(
        member_handle: &str,
        kid: &str,
        attestor_pub: Option<String>,
        verified_github: Option<&VerifiedGithubIdentity>,
    ) -> Self {
        match verified_github {
            Some(verified_github) => {
                Self::verified_github(member_handle, kid, attestor_pub, verified_github)
            }
            None => Self::manual_review(member_handle, kid, attestor_pub),
        }
    }

    fn manual_review(member_handle: &str, kid: &str, attestor_pub: Option<String>) -> Self {
        Self {
            member_handle: MemberHandle::try_from(member_handle)
                .expect("approved member_handle must be valid"),
            kid: Kid::try_from(kid).expect("approved kid must be valid"),
            github_id: None,
            github_login: None,
            attestor_pub,
        }
    }

    fn verified_github(
        member_handle: &str,
        kid: &str,
        attestor_pub: Option<String>,
        verified_github: &VerifiedGithubIdentity,
    ) -> Self {
        Self {
            member_handle: MemberHandle::try_from(member_handle)
                .expect("approved member_handle must be valid"),
            kid: Kid::try_from(kid).expect("approved kid must be valid"),
            github_id: Some(verified_github.id),
            github_login: Some(verified_github.login.clone()),
            attestor_pub,
        }
    }

    fn to_known_key_with_approved_at(&self, approved_at: String) -> KnownKey {
        KnownKey {
            kid: self.kid.to_string(),
            subject_handle: self.member_handle.to_string(),
            approved_at,
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: build_evidence(
                self.github_id,
                self.github_login.clone(),
                self.attestor_pub.clone(),
            ),
            extra: BTreeMap::new(),
        }
    }

    fn into_known_key(self) -> Result<KnownKey> {
        Ok(self.to_known_key_with_approved_at(generate_current_timestamp()?))
    }
}

impl From<&TrustApprovalCandidate> for ApprovedKnownKey {
    fn from(candidate: &TrustApprovalCandidate) -> Self {
        Self::from_review(
            &candidate.member_handle,
            &candidate.kid,
            candidate.attestor_pub.clone(),
            candidate.verified_github.as_ref(),
        )
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
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    approvals: &[ApprovedKnownKey],
) -> Result<usize> {
    if approvals.is_empty() {
        return Ok(0);
    }

    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::CreateIfMissing,
        TrustStoreWriteBinding::MergedApproval,
        |protected| {
            let mut added = 0usize;

            for approval in approvals {
                let identity = KnownKeyIdentity::from(approval);
                enforce_non_self_approval(&execution.member_handle, identity.member_handle())?;
                let known_key = approval.clone().into_known_key()?;
                if add_known_key(&mut protected.known_keys, known_key)? {
                    added += 1;
                }
            }

            Ok(TrustStoreMutation {
                value: added,
                changed: added > 0,
            })
        },
    )
}

/// Mode one recipient-set approval is written with.
const RECIPIENT_SET_APPROVAL_MODE: TrustStoreMutationMode = TrustStoreMutationMode::CreateIfMissing;

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
    execution: &ExecutionContext,
) -> Result<ObservedTrustStore> {
    observe_execution_trust_store(execution, RECIPIENT_SET_APPROVAL_MODE)
}

/// Store the recipient-set approval an operator just agreed to.
///
/// `observed` is the store the decision was made against, and the commit
/// accepts nothing else.
pub(crate) fn save_reviewed_recipient_set_approval(
    execution: &ExecutionContext,
    observed: &ObservedTrustStore,
    approval: ArtifactRecipientSet,
) -> Result<usize> {
    execute_trust_store_mutation_with_preparation(
        execution,
        RECIPIENT_SET_APPROVAL_MODE,
        observed.prepared(),
        |protected| apply_recipient_set_approval(protected, approval),
    )
}

/// Put the approved recipient set into the content the commit settled on.
fn apply_recipient_set_approval(
    protected: &mut TrustStoreProtected,
    approval: ArtifactRecipientSet,
) -> Result<TrustStoreMutation<usize>> {
    let changed = upsert_recipient_set(
        &mut protected.recipient_sets,
        approval,
        generate_current_timestamp()?,
    );
    Ok(TrustStoreMutation {
        value: usize::from(changed),
        changed,
    })
}

fn enforce_non_self_approval(owner_handle: &str, member_handle: &str) -> Result<()> {
    if member_handle == owner_handle {
        return Err(Error::build_invalid_operation_error(format!(
            "Self member '{}' must not be stored in known_keys",
            member_handle
        )));
    }
    Ok(())
}

fn build_evidence(
    github_id: Option<u64>,
    github_login: Option<String>,
    attestor_pub: Option<String>,
) -> Option<KnownKeyEvidence> {
    let github_account = github_id.map(|id| KnownKeyGithubAccount {
        id,
        login: github_login,
    });

    if github_account.is_none() && attestor_pub.is_none() {
        return None;
    }

    Some(KnownKeyEvidence {
        github_account,
        ssh_attestor_pub: attestor_pub,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_approval_test.rs"]
mod tests;
