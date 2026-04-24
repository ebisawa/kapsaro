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
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::identity::{Kid, MemberId};
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount,
};
use crate::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovedKnownKey {
    member_id: MemberId,
    kid: Kid,
    github_id: Option<u64>,
    github_login: Option<String>,
    attestor_pub: Option<String>,
}

pub(crate) type ApprovalSaveResult = TrustMutationResult<usize>;

impl ApprovedKnownKey {
    pub(crate) fn from_review(
        member_id: &str,
        kid: &str,
        attestor_pub: Option<String>,
        verified_github: Option<&VerifiedGithubIdentity>,
    ) -> Self {
        match verified_github {
            Some(verified_github) => {
                Self::verified_github(member_id, kid, attestor_pub, verified_github)
            }
            None => Self::manual_review(member_id, kid, attestor_pub),
        }
    }

    fn manual_review(member_id: &str, kid: &str, attestor_pub: Option<String>) -> Self {
        Self {
            member_id: MemberId::try_from(member_id).expect("approved member_id must be valid"),
            kid: Kid::try_from(kid).expect("approved kid must be valid"),
            github_id: None,
            github_login: None,
            attestor_pub,
        }
    }

    fn verified_github(
        member_id: &str,
        kid: &str,
        attestor_pub: Option<String>,
        verified_github: &VerifiedGithubIdentity,
    ) -> Self {
        Self {
            member_id: MemberId::try_from(member_id).expect("approved member_id must be valid"),
            kid: Kid::try_from(kid).expect("approved kid must be valid"),
            github_id: Some(verified_github.id),
            github_login: Some(verified_github.login.clone()),
            attestor_pub,
        }
    }

    fn to_known_key_with_approved_at(&self, approved_at: String) -> KnownKey {
        KnownKey {
            kid: self.kid.to_string(),
            member_id: self.member_id.to_string(),
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
            &candidate.member_id,
            &candidate.kid,
            candidate.attestor_pub.clone(),
            candidate.verified_github.as_ref(),
        )
    }
}

impl From<&ApprovedKnownKey> for KnownKeyIdentity {
    fn from(value: &ApprovedKnownKey) -> Self {
        Self::new(value.member_id.clone(), value.kid.clone())
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
        options.verbose,
        |protected| {
            let mut added = 0usize;

            for approval in approvals {
                let identity = KnownKeyIdentity::from(approval);
                enforce_non_self_approval(&execution.member_id, identity.member_id())?;
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

fn enforce_non_self_approval(owner_member_id: &str, member_id: &str) -> Result<()> {
    if member_id == owner_member_id {
        return Err(Error::InvalidOperation {
            message: format!(
                "Self member '{}' must not be stored in known_keys",
                member_id
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
#[path = "../../../tests/unit/app_trust_approval_test.rs"]
mod tests;
