// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared trust store approval persistence.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::{
    build_now_timestamp, execute_trust_store_mutation_with_execution, TrustStoreMutation,
    TrustStoreMutationMode,
};
use crate::app::trust::types::TrustMutationResult;
use crate::app::trust::TrustApprovalCandidate;
use crate::feature::trust::known_keys::add_known_key;
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::feature::trust::recipient_sets::{upsert_recipient_set, ArtifactRecipientSet};
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount,
};
use crate::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovedKnownKey {
    member_handle: MemberHandle,
    kid: Kid,
    github_id: Option<u64>,
    github_login: Option<String>,
    attestor_pub: Option<String>,
}

pub(crate) type ApprovalSaveResult = TrustMutationResult<usize>;

impl ApprovedKnownKey {
    pub(crate) fn from_review(
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
        Ok(self.to_known_key_with_approved_at(build_now_timestamp()?))
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

pub(crate) fn save_known_key_approvals(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    approvals: &[ApprovedKnownKey],
) -> Result<ApprovalSaveResult> {
    if approvals.is_empty() {
        return Ok(TrustMutationResult::new(0, Vec::new()));
    }

    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::CreateIfMissing,
        options.debug,
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

pub(crate) fn save_recipient_set_approval(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    approval: Option<ArtifactRecipientSet>,
) -> Result<ApprovalSaveResult> {
    let Some(approval) = approval else {
        return Ok(TrustMutationResult::new(0, Vec::new()));
    };

    execute_trust_store_mutation_with_execution(
        options,
        execution,
        TrustStoreMutationMode::CreateIfMissing,
        options.debug,
        |protected| {
            let changed = upsert_recipient_set(
                &mut protected.recipient_sets,
                approval,
                build_now_timestamp()?,
            );
            Ok(TrustStoreMutation {
                value: usize::from(changed),
                changed,
            })
        },
    )
}

fn enforce_non_self_approval(owner_handle: &str, member_handle: &str) -> Result<()> {
    if member_handle == owner_handle {
        return Err(Error::InvalidOperation {
            message: format!(
                "Self member '{}' must not be stored in known_keys",
                member_handle
            ),
        });
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
