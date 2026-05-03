// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust enforcement: apply trust judgments to command execution.

use crate::app::trust::policy::CommandCapability;
use crate::app::trust::snapshot::TrustContext;
use crate::feature::trust::judgment::{
    judge_recipients_trust_with_additional, AdditionalKnownKeyCache, TrustIdentity, TrustJudgment,
};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::{Error, Result};

/// Review material for a manual trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustApprovalCandidate {
    pub member_handle: MemberHandle,
    pub kid: Kid,
    pub fingerprint: Option<String>,
    pub github_id: Option<u64>,
    pub github_login: Option<String>,
    pub attestor_pub: Option<String>,
    pub verified_github: Option<VerifiedGithubIdentity>,
    pub github_binding_configured: bool,
    pub online_verification_attempted: bool,
    pub online_verification_message: Option<String>,
    pub public_key: Option<PublicKey>,
    pub requires_out_of_band_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignerTrustOutcome {
    Accepted,
    NeedsKnownKeyApproval(TrustApprovalCandidate),
    NeedsNonMemberAcceptance {
        candidate: TrustApprovalCandidate,
        current_recipients: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecipientTrustOutcome {
    Accepted,
    NeedsManualApproval(Vec<TrustApprovalCandidate>),
}

pub(crate) fn enforce_signer_trust(
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
        } => Err(Error::Verify {
            rule: "E_TRUST_ACTIVE_MEMBER_MISMATCH".to_string(),
            message: format!(
                "Signer '{}' (kid: {}) does not match current active member '{}'",
                member_handle, kid, active_member_handle
            ),
        }),
        TrustJudgment::KnownKeyIntegrityAnomaly {
            member_handle,
            kid,
            known_member_handle,
        } => Err(Error::Verify {
            rule: "E_TRUST_KID_INTEGRITY_ANOMALY".to_string(),
            message: format!(
                "kid '{}' exists with subject_handle '{}' but candidate has subject_handle '{}'",
                kid, known_member_handle, member_handle
            ),
        }),
    }
}

pub(crate) fn enforce_recipients_trust(
    trust_ctx: &TrustContext,
    recipients: &[PublicKey],
) -> Result<RecipientTrustOutcome> {
    enforce_recipients_trust_with_additional(trust_ctx, recipients, &[])
}

pub(crate) fn enforce_recipients_trust_with_additional(
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
        return Err(Error::Verify {
            rule: "E_TRUST_RECIPIENT_UNKNOWN".to_string(),
            message: format!(
                "Unknown recipient kid(s): {}. Run 'member verify --approve' first.",
                kids.join(", ")
            ),
        });
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

fn enforce_scope_strict_mode(
    trust_ctx: &TrustContext,
    capability: CommandCapability,
) -> Result<()> {
    if capability.allows_strict_key_checking_no() || !trust_ctx.strict_key_checking.is_disabled() {
        return Ok(());
    }

    Err(Error::InvalidOperation {
        message: format!(
            "SECRETENV_STRICT_KEY_CHECKING=no is not allowed for {}",
            capability.label()
        ),
    })
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
        Err(Error::Verify {
            rule: "E_TRUST_UNKNOWN_SIGNER".to_string(),
            message: format!(
                "Unknown signer kid '{}' (member: {}) in non-interactive mode",
                kid, member_handle
            ),
        })
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
        Err(Error::Verify {
            rule: "E_TRUST_NON_MEMBER".to_string(),
            message: format!(
                "Signer '{}' (kid: {}) is not in active members",
                member_handle, kid
            ),
        })
    }
}

pub(crate) fn build_trust_approval_candidate(public_key: &PublicKey) -> TrustApprovalCandidate {
    let github = public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|claims| claims.github_account.as_ref());

    TrustApprovalCandidate {
        member_handle: MemberHandle::try_from(public_key.protected.subject_handle.clone())
            .expect("public key member_handle must be valid"),
        kid: Kid::try_from(public_key.protected.kid.clone()).expect("public key kid must be valid"),
        fingerprint: build_sha256_fingerprint(&public_key.protected.identity.attestation.pub_).ok(),
        github_id: None,
        github_login: None,
        attestor_pub: Some(public_key.protected.identity.attestation.pub_.clone()),
        verified_github: None,
        github_binding_configured: github.is_some(),
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: Some(public_key.clone()),
        requires_out_of_band_verification: true,
    }
}

pub(crate) fn build_signer_identity(public_key: &PublicKey) -> Result<TrustIdentity> {
    TrustIdentity::from_public_key(public_key)
}
