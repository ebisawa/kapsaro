// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust enforcement: apply trust judgments to command execution.

use crate::app::trust::policy::CommandCapability;
use crate::app::trust::snapshot::TrustContext;
use crate::feature::trust::judgment::{
    judge_recipients_trust_with_additional, AdditionalKnownKeyCache, TrustIdentity, TrustJudgment,
};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::feature::trust::recipient_sets::{
    find_recipient_handle_mismatch, is_self_only_recipient_set, is_signer_in_recipient_set,
    judge_recipient_set, ArtifactRecipientSet, RecipientSetJudgment,
};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::trust_store::RecipientSetRecord;
use crate::{Error, Result};

use super::candidate::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerTrustOutcome {
    Accepted,
    NeedsKnownKeyApproval(TrustApprovalCandidate),
    NeedsNonMemberAcceptance {
        candidate: TrustApprovalCandidate,
        current_recipients: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientTrustOutcome {
    Accepted,
    NeedsManualApproval(Vec<TrustApprovalCandidate>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactRecipientTrustOutcome {
    Accepted,
    SkippedStrictKeyCheckingNo,
    NeedsManualApproval(Box<ArtifactRecipientSetReview>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecipientSetReview {
    pub current: ArtifactRecipientSet,
    pub approved: Option<RecipientSetRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecipientKeyTrust {
    pub outcome: RecipientTrustOutcome,
    pub warnings: Vec<String>,
}

pub fn enforce_signer_trust(
    trust_ctx: &TrustContext,
    judgment: &TrustJudgment,
    public_key: &PublicKey,
    capability: CommandCapability,
    current_recipients: &[String],
) -> Result<SignerTrustOutcome> {
    enforce_scope_strict_mode(trust_ctx, capability)?;
    let candidate = build_trust_approval_candidate(public_key);

    match judgment {
        TrustJudgment::Trusted => Ok(SignerTrustOutcome::Accepted),
        TrustJudgment::NeedsApproval { member_handle, kid } => {
            enforce_needs_approval(trust_ctx, capability, member_handle, kid, candidate)
        }
        TrustJudgment::NonMember { member_handle, kid } => enforce_non_member(
            trust_ctx,
            capability,
            member_handle,
            kid,
            candidate,
            current_recipients,
        ),
        TrustJudgment::ActiveMemberMismatch {
            member_handle,
            kid,
            active_member_handle,
        } => Err(Error::build_verification_error(
            "E_TRUST_ACTIVE_MEMBER_MISMATCH".to_string(),
            format!(
                "Signer '{}' (kid: {}) does not match current active member '{}'",
                member_handle, kid, active_member_handle
            ),
        )),
        TrustJudgment::KnownKeyIntegrityAnomaly {
            member_handle,
            kid,
            known_member_handle,
        } => Err(Error::build_verification_error(
            "E_TRUST_KID_INTEGRITY_ANOMALY".to_string(),
            format!(
                "kid '{}' exists with subject_handle '{}' but candidate has subject_handle '{}'",
                kid, known_member_handle, member_handle
            ),
        )),
    }
}

pub fn enforce_recipients_trust(
    trust_ctx: &TrustContext,
    recipients: &[PublicKey],
) -> Result<RecipientTrustOutcome> {
    enforce_recipients_trust_with_additional(trust_ctx, recipients, &[])
}

pub fn enforce_recipients_trust_with_additional(
    trust_ctx: &TrustContext,
    recipients: &[PublicKey],
    additional_known_keys: &[KnownKeyIdentity],
) -> Result<RecipientTrustOutcome> {
    let recipient_trust_identities = recipients
        .iter()
        .map(TrustIdentity::from_public_key)
        .collect::<Result<Vec<_>>>()?;
    let known_key_cache =
        AdditionalKnownKeyCache::new(&trust_ctx.known_keys, additional_known_keys);
    known_key_cache.validate_recipient_integrity(&recipient_trust_identities)?;

    let needs_approval = judge_recipients_trust_with_additional(
        &recipient_trust_identities,
        &known_key_cache,
        &trust_ctx.self_trust,
    )?;

    if needs_approval.is_empty() {
        return Ok(RecipientTrustOutcome::Accepted);
    }

    if !trust_ctx.is_interactive {
        let kids: Vec<String> = needs_approval
            .iter()
            .map(|identity| format!("'{}' ({})", identity.kid(), identity.member_handle()))
            .collect();
        return Err(Error::build_verification_error(
            "E_TRUST_RECIPIENT_UNKNOWN".to_string(),
            format!(
                "Unknown recipient kid(s): {}. Run 'member verify --approve' first.",
                kids.join(", ")
            ),
        ));
    }

    let pending: Vec<TrustApprovalCandidate> = needs_approval
        .iter()
        .filter_map(|identity| {
            recipients
                .iter()
                .find(|pk| {
                    pk.protected.subject_handle == identity.member_handle()
                        && pk.protected.kid == identity.kid()
                })
                .map(build_trust_approval_candidate)
        })
        .collect();
    Ok(RecipientTrustOutcome::NeedsManualApproval(pending))
}

pub fn enforce_artifact_recipient_set_trust(
    trust_ctx: &TrustContext,
    signer_kid: &str,
    current: &ArtifactRecipientSet,
    capability: CommandCapability,
) -> Result<ArtifactRecipientTrustOutcome> {
    enforce_recipient_handle_consistency(trust_ctx, current)?;

    if capability.allows_strict_key_checking_no() && trust_ctx.strict_key_checking.is_disabled() {
        return Ok(ArtifactRecipientTrustOutcome::SkippedStrictKeyCheckingNo);
    }

    match judge_recipient_set(&trust_ctx.recipient_sets, current) {
        RecipientSetJudgment::Accepted => {
            enforce_signer_in_reviewed_member_set(signer_kid, current)?;
            Ok(ArtifactRecipientTrustOutcome::Accepted)
        }
        RecipientSetJudgment::Missing => {
            enforce_signer_in_reviewed_member_set(signer_kid, current)?;
            if is_self_only_recipient_set(
                current,
                &trust_ctx.active_members_by_kid,
                &trust_ctx.self_trust,
            )? {
                return Ok(ArtifactRecipientTrustOutcome::Accepted);
            }
            enforce_artifact_recipient_review(
                trust_ctx,
                current.clone(),
                None,
                "E_RECIPIENT_TRUST_MISSING",
            )
        }
        RecipientSetJudgment::Changed { approved } => {
            enforce_signer_in_reviewed_member_set(signer_kid, current)?;
            if is_self_only_recipient_set(
                current,
                &trust_ctx.active_members_by_kid,
                &trust_ctx.self_trust,
            )? {
                return Ok(ArtifactRecipientTrustOutcome::Accepted);
            }
            enforce_artifact_recipient_review(
                trust_ctx,
                current.clone(),
                Some(approved),
                "E_RECIPIENT_SET_CHANGED",
            )
        }
    }
}

pub fn evaluate_read_artifact_recipient_keys(
    trust_ctx: &TrustContext,
    signer_kid: &str,
    current: &ArtifactRecipientSet,
) -> Result<ReadRecipientKeyTrust> {
    enforce_recipient_handle_consistency(trust_ctx, current)?;
    enforce_signer_in_reviewed_member_set(signer_kid, current)?;

    let (recipients, warnings) = resolve_active_artifact_recipients(trust_ctx, current);
    let outcome = if trust_ctx.strict_key_checking.is_disabled() {
        RecipientTrustOutcome::Accepted
    } else {
        enforce_recipients_trust(trust_ctx, &recipients)?
    };

    Ok(ReadRecipientKeyTrust { outcome, warnings })
}

pub fn enforce_write_input_artifact_recipients(
    trust_ctx: &TrustContext,
    signer_kid: &str,
    current: &ArtifactRecipientSet,
) -> Result<()> {
    enforce_recipient_handle_consistency(trust_ctx, current)?;
    enforce_signer_in_reviewed_member_set(signer_kid, current)?;

    if let Some(kid) = current
        .recipient_kids()
        .iter()
        .find(|kid| !trust_ctx.active_members_by_kid.contains_key(*kid))
    {
        return Err(Error::build_verification_error("E_ARTIFACT_RECIPIENT_NOT_ACTIVE".to_string(), format!(
                "Artifact contains recipient kid '{}' that is not in current members/active. Run 'secretenv rewrap' before writing it.",
                kid
            )));
    }

    Ok(())
}

fn resolve_active_artifact_recipients(
    trust_ctx: &TrustContext,
    current: &ArtifactRecipientSet,
) -> (Vec<PublicKey>, Vec<String>) {
    let mut recipients = Vec::new();
    let mut warnings = Vec::new();
    for kid in current.recipient_kids() {
        match trust_ctx.active_members_by_kid.get(kid) {
            Some(public_key) => recipients.push(public_key.clone()),
            None => warnings.push(format!(
                "Recipient kid '{}' is not in current members/active; this artifact may contain a stale or historical recipient. Run 'secretenv rewrap' before writing it.",
                kid
            )),
        }
    }
    (recipients, warnings)
}

fn enforce_recipient_handle_consistency(
    trust_ctx: &TrustContext,
    current: &ArtifactRecipientSet,
) -> Result<()> {
    if let Some(mismatch) =
        find_recipient_handle_mismatch(current, &trust_ctx.active_members_by_kid)
    {
        return Err(Error::build_verification_error("E_RECIPIENT_SET_HANDLE_MISMATCH".to_string(), format!(
                "Recipient kid '{}' is labeled as '{}' in artifact wrap, but members/active labels it as '{}'",
                mismatch.kid, mismatch.artifact_recipient_handle, mismatch.active_member_handle
            )));
    }
    Ok(())
}

fn enforce_signer_in_reviewed_member_set(
    signer_kid: &str,
    current: &ArtifactRecipientSet,
) -> Result<()> {
    let signer_kid = Kid::try_from(signer_kid.to_string())?.into_string();
    if is_signer_in_recipient_set(&signer_kid, current)? {
        return Ok(());
    }

    Err(Error::build_verification_error(
        "E_RECIPIENT_SET_SIGNER_NOT_INCLUDED".to_string(),
        format!(
            "Signer key '{}' is not included in the member set for this secret",
            signer_kid
        ),
    ))
}

fn enforce_artifact_recipient_review(
    trust_ctx: &TrustContext,
    current: ArtifactRecipientSet,
    approved: Option<RecipientSetRecord>,
    rule: &str,
) -> Result<ArtifactRecipientTrustOutcome> {
    if trust_ctx.is_interactive {
        return Ok(ArtifactRecipientTrustOutcome::NeedsManualApproval(
            Box::new(ArtifactRecipientSetReview { current, approved }),
        ));
    }

    Err(Error::build_verification_error(
        rule.to_string(),
        recipient_set_review_required_message(rule).to_string(),
    ))
}

fn recipient_set_review_required_message(rule: &str) -> &'static str {
    match rule {
        "E_RECIPIENT_SET_CHANGED" => {
            "This secret's member set has changed since the last review on this device. Run the command interactively to review it first."
        }
        _ => {
            "This secret's member set has not been reviewed on this device. Run the command interactively to review it first."
        }
    }
}

fn enforce_scope_strict_mode(
    trust_ctx: &TrustContext,
    capability: CommandCapability,
) -> Result<()> {
    if capability.allows_strict_key_checking_no() || !trust_ctx.strict_key_checking.is_disabled() {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(format!(
        "SECRETENV_STRICT_KEY_CHECKING=no is not allowed for {}",
        capability.label()
    )))
}

fn enforce_needs_approval(
    trust_ctx: &TrustContext,
    capability: CommandCapability,
    member_handle: &MemberHandle,
    kid: &Kid,
    candidate: TrustApprovalCandidate,
) -> Result<SignerTrustOutcome> {
    if capability.allows_strict_key_checking_no() && trust_ctx.strict_key_checking.is_disabled() {
        Ok(SignerTrustOutcome::Accepted)
    } else {
        enforce_manual_approval(trust_ctx, member_handle, kid, candidate)
    }
}

fn enforce_manual_approval(
    trust_ctx: &TrustContext,
    member_handle: &MemberHandle,
    kid: &Kid,
    candidate: TrustApprovalCandidate,
) -> Result<SignerTrustOutcome> {
    if trust_ctx.is_interactive {
        Ok(SignerTrustOutcome::NeedsKnownKeyApproval(candidate))
    } else {
        Err(Error::build_verification_error(
            "E_TRUST_UNKNOWN_SIGNER".to_string(),
            format!(
                "Unknown signer kid '{}' (member: {}) in non-interactive mode",
                kid, member_handle
            ),
        ))
    }
}

fn enforce_non_member(
    trust_ctx: &TrustContext,
    capability: CommandCapability,
    member_handle: &MemberHandle,
    kid: &Kid,
    candidate: TrustApprovalCandidate,
    current_recipients: &[String],
) -> Result<SignerTrustOutcome> {
    if capability.allows_non_member_acceptance() && trust_ctx.is_interactive {
        Ok(SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate,
            current_recipients: current_recipients.to_vec(),
        })
    } else {
        Err(Error::build_verification_error(
            "E_TRUST_NON_MEMBER".to_string(),
            format!(
                "Signer '{}' (kid: {}) is not in active members",
                member_handle, kid
            ),
        ))
    }
}

pub fn build_trust_approval_candidate(public_key: &PublicKey) -> TrustApprovalCandidate {
    TrustApprovalCandidateBuilder::from_public_key(public_key).build()
}

pub fn build_signer_identity(public_key: &PublicKey) -> Result<TrustIdentity> {
    TrustIdentity::from_public_key(public_key)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_enforcement_recipient_set_test.rs"]
mod recipient_set_tests;
