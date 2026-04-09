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
            return Ok(TrustJudgment::NonMember {
                member_id: signer.member_id_value().clone(),
                kid: signer.kid_value().clone(),
            });
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

    Ok(match match_known(signer) {
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
    })
}

fn is_self_key(identity: &TrustIdentity, self_trust: &SelfTrustSet) -> Result<bool> {
    self_trust.contains_identity(identity)
}
