// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::identity::{Kid, MemberId};
use crate::Result;

use super::active_member::{ActiveMemberSnapshot, CurrentMemberMatch};
use super::identity::TrustIdentity;
use super::known_key::{AdditionalKnownKeyCache, KnownKeyCache, KnownKeyMatch};
use super::self_trust::SelfTrustSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustJudgment {
    Trusted,
    NeedsApproval {
        member_id: MemberId,
        kid: Kid,
    },
    NonMember {
        member_id: MemberId,
        kid: Kid,
    },
    ActiveMemberMismatch {
        member_id: MemberId,
        kid: Kid,
        active_member_id: MemberId,
    },
    KnownKeyIntegrityAnomaly {
        member_id: MemberId,
        kid: Kid,
        known_member_id: MemberId,
    },
}

pub fn judge_signer_trust(
    signer: &TrustIdentity,
    active_members: &ActiveMemberSnapshot<'_>,
    known_keys: &KnownKeyCache<'_>,
    self_trust: &SelfTrustSet,
) -> Result<TrustJudgment> {
    judge_signer_trust_with_match(signer, active_members, self_trust, |identity| {
        known_keys.match_identity(identity)
    })
}

pub(crate) fn judge_signer_trust_with_additional(
    signer: &TrustIdentity,
    active_members: &ActiveMemberSnapshot<'_>,
    known_keys: &AdditionalKnownKeyCache<'_>,
    self_trust: &SelfTrustSet,
) -> Result<TrustJudgment> {
    judge_signer_trust_with_match(signer, active_members, self_trust, |identity| {
        known_keys.match_identity(identity)
    })
}

fn judge_signer_trust_with_match<MatchKnown>(
    signer: &TrustIdentity,
    active_members: &ActiveMemberSnapshot<'_>,
    self_trust: &SelfTrustSet,
    match_known: MatchKnown,
) -> Result<TrustJudgment>
where
    MatchKnown: Fn(&TrustIdentity) -> KnownKeyMatch,
{
    match active_members.match_identity(signer) {
        CurrentMemberMatch::Missing => {
            return evaluate_missing_active_member(signer, self_trust);
        }
        CurrentMemberMatch::MemberIdMismatch { active_member_id } => {
            return Ok(TrustJudgment::ActiveMemberMismatch {
                member_id: signer.member_id_value().clone(),
                kid: signer.kid_value().clone(),
                active_member_id,
            });
        }
        CurrentMemberMatch::Matched => {}
    }

    if is_self_key(signer, self_trust)? {
        return Ok(TrustJudgment::Trusted);
    }

    Ok(build_known_key_judgment(signer, match_known(signer)))
}

/// Decide the judgment when the signer is not present in the active member set.
///
/// Historical self signers remain trusted from the local keystore without
/// falling back to one-shot non-member acceptance.
fn evaluate_missing_active_member(
    signer: &TrustIdentity,
    self_trust: &SelfTrustSet,
) -> Result<TrustJudgment> {
    if is_self_key(signer, self_trust)? {
        return Ok(TrustJudgment::Trusted);
    }
    Ok(TrustJudgment::NonMember {
        member_id: signer.member_id_value().clone(),
        kid: signer.kid_value().clone(),
    })
}

fn build_known_key_judgment(signer: &TrustIdentity, match_result: KnownKeyMatch) -> TrustJudgment {
    match match_result {
        KnownKeyMatch::Exact => TrustJudgment::Trusted,
        KnownKeyMatch::Missing => TrustJudgment::NeedsApproval {
            member_id: signer.member_id_value().clone(),
            kid: signer.kid_value().clone(),
        },
        KnownKeyMatch::MemberIdMismatch { known_member_id } => {
            TrustJudgment::KnownKeyIntegrityAnomaly {
                member_id: signer.member_id_value().clone(),
                kid: signer.kid_value().clone(),
                known_member_id,
            }
        }
    }
}

fn is_self_key(identity: &TrustIdentity, self_trust: &SelfTrustSet) -> Result<bool> {
    self_trust.contains_identity(identity)
}
