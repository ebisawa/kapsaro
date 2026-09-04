// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Decides the overall trust judgment for a document's signer.
//! Combines active-member and known-key matching into one Trusted/NeedsApproval/NonMember/anomaly outcome.

use crate::feature::trust::known_keys::build_kid_integrity_anomaly_error;
use crate::model::identity::{Kid, MemberHandle};
use crate::{Error, Result};

use super::active_member::{ActiveMemberSnapshot, CurrentMemberMatch};
use super::identity::TrustIdentity;
use super::known_key::{KnownKeyCache, KnownKeyMatch};
use super::self_trust::SelfTrustSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustJudgment {
    Trusted,
    NeedsApproval {
        member_handle: MemberHandle,
        kid: Kid,
    },
    NonMember {
        member_handle: MemberHandle,
        kid: Kid,
    },
    ActiveMemberMismatch {
        member_handle: MemberHandle,
        kid: Kid,
        active_member_handle: MemberHandle,
    },
    KnownKeyIntegrityAnomaly {
        member_handle: MemberHandle,
        kid: Kid,
        known_member_handle: MemberHandle,
    },
}

pub fn judge_signer_trust(
    signer: &TrustIdentity,
    active_members: &ActiveMemberSnapshot<'_>,
    known_keys: &KnownKeyCache<'_>,
    self_trust: &SelfTrustSet,
) -> Result<TrustJudgment> {
    judge_signer_trust_with_match(signer, active_members, self_trust, |identity| {
        known_keys.judge_identity_match(identity)
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
    match active_members.judge_identity_match(signer) {
        CurrentMemberMatch::Missing => {
            return judge_missing_active_member(signer, self_trust);
        }
        CurrentMemberMatch::MemberHandleMismatch {
            active_member_handle,
        } => {
            return Ok(TrustJudgment::ActiveMemberMismatch {
                member_handle: signer.member_handle_value().clone(),
                kid: signer.kid_value().clone(),
                active_member_handle: MemberHandle::try_from(active_member_handle)?,
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
fn judge_missing_active_member(
    signer: &TrustIdentity,
    self_trust: &SelfTrustSet,
) -> Result<TrustJudgment> {
    if is_self_key(signer, self_trust)? {
        return Ok(TrustJudgment::Trusted);
    }
    Ok(TrustJudgment::NonMember {
        member_handle: signer.member_handle_value().clone(),
        kid: signer.kid_value().clone(),
    })
}

fn build_known_key_judgment(signer: &TrustIdentity, match_result: KnownKeyMatch) -> TrustJudgment {
    match match_result {
        KnownKeyMatch::Exact => TrustJudgment::Trusted,
        KnownKeyMatch::Missing => TrustJudgment::NeedsApproval {
            member_handle: signer.member_handle_value().clone(),
            kid: signer.kid_value().clone(),
        },
        KnownKeyMatch::MemberHandleMismatch {
            known_member_handle,
        } => TrustJudgment::KnownKeyIntegrityAnomaly {
            member_handle: signer.member_handle_value().clone(),
            kid: signer.kid_value().clone(),
            known_member_handle,
        },
    }
}

fn is_self_key(identity: &TrustIdentity, self_trust: &SelfTrustSet) -> Result<bool> {
    self_trust.contains_identity(identity)
}

/// What a signer judgment leaves for the caller to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerAcceptance {
    Trusted,
    NeedsApproval {
        member_handle: MemberHandle,
        kid: Kid,
    },
}

/// Turn one signer judgment into acceptance, or the error it states.
///
/// Every judgment that no review can answer is refused here, so a signer that
/// is no member, that collides with an active member, or whose kid is already
/// bound to another member reads the same way to every caller.
pub fn enforce_signer_judgment(judgment: TrustJudgment) -> Result<SignerAcceptance> {
    match judgment {
        TrustJudgment::Trusted => Ok(SignerAcceptance::Trusted),
        TrustJudgment::NeedsApproval { member_handle, kid } => {
            Ok(SignerAcceptance::NeedsApproval { member_handle, kid })
        }
        TrustJudgment::NonMember { member_handle, kid } => {
            Err(build_non_member_error(&member_handle, &kid))
        }
        TrustJudgment::ActiveMemberMismatch {
            member_handle,
            kid,
            active_member_handle,
        } => Err(build_active_member_mismatch_error(
            &member_handle,
            &kid,
            &active_member_handle,
        )),
        TrustJudgment::KnownKeyIntegrityAnomaly {
            member_handle,
            kid,
            known_member_handle,
        } => Err(build_kid_integrity_anomaly_error(
            kid.as_str(),
            known_member_handle.as_str(),
            member_handle.as_str(),
        )),
    }
}

fn build_non_member_error(member_handle: &MemberHandle, kid: &Kid) -> Error {
    Error::build_verification_error(
        "E_TRUST_NON_MEMBER".to_string(),
        format!(
            "Signer is not in active members.\nsigner: {}\nkid: {}",
            member_handle, kid
        ),
    )
}

fn build_active_member_mismatch_error(
    member_handle: &MemberHandle,
    kid: &Kid,
    active_member_handle: &MemberHandle,
) -> Error {
    Error::build_verification_error(
        "E_TRUST_ACTIVE_MEMBER_MISMATCH".to_string(),
        format!(
            "Signer '{}' (kid: {}) does not match current active member '{}'",
            member_handle, kid, active_member_handle
        ),
    )
}
