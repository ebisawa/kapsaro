// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust evaluation helpers built on immutable command snapshots.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::enforcement::{
    build_signer_identity, enforce_artifact_recipient_set_trust, enforce_signer_trust,
    evaluate_read_artifact_recipient_keys,
};
use crate::app::trust::policy::{CommandCapability, ReadTrustPolicy, TrustPolicy};
use crate::app::trust::snapshot::{load_read_trust_context, TrustContext};
use crate::app::trust::{ArtifactRecipientTrustOutcome, RecipientTrustOutcome, SignerTrustOutcome};
use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::trust::judgment::{
    judge_signer_trust_with_additional, AdditionalKnownKeyCache,
};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::model::verification::SignatureVerificationProof;
use crate::support::kid::format_kid_half_display_lossy;
use crate::support::warning::push_unique_warning;
use crate::Result;
use tracing::debug;

pub struct ReadArtifactTrustPlan {
    pub signer_outcome: SignerTrustOutcome,
    pub recipient_outcome: RecipientTrustOutcome,
    pub warnings: Vec<String>,
}

pub fn evaluate_read_artifact_trust<P>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    proof: &SignatureVerificationProof,
    current_recipient_set: &ArtifactRecipientSet,
    current_recipients: &[String],
) -> Result<ReadArtifactTrustPlan>
where
    P: ReadTrustPolicy,
{
    let workspace = execution.workspace_root.as_ref().ok_or_else(|| {
        crate::Error::build_invalid_operation_error(format!(
            "Workspace is required for {} trust evaluation",
            P::CAPABILITY.label()
        ))
    })?;
    let loaded = load_read_trust_context(
        options,
        &workspace.root_path,
        &execution.member_handle,
        Some(execution.key_ctx.self_signature_public_key_x()),
        Some(execution.key_ctx.local_key_identity()),
        options.debug,
    )?;
    let trust_ctx = &loaded.trust_ctx;
    let signer_outcome =
        evaluate_signer_trust_with_proof(trust_ctx, proof, P::CAPABILITY, current_recipients)?;
    let recipient_trust = evaluate_read_artifact_recipient_keys(trust_ctx, current_recipient_set)?;
    if options.debug {
        debug!(
            "[TRUST] read evaluation: capability={}, signer_kid={}, recipient_count={}, stale_recipient_warnings={}",
            P::CAPABILITY.label(),
            format_kid_half_display_lossy(&proof.kid),
            current_recipient_set.recipient_kids().len(),
            recipient_trust.warnings.len()
        );
    }
    let mut warnings = loaded.warnings;
    warnings.extend(recipient_trust.warnings);
    Ok(ReadArtifactTrustPlan {
        signer_outcome,
        recipient_outcome: recipient_trust.outcome,
        warnings,
    })
}

pub fn evaluate_signer_trust_with_proof(
    trust_ctx: &TrustContext,
    proof: &SignatureVerificationProof,
    capability: CommandCapability,
    current_recipients: &[String],
) -> Result<SignerTrustOutcome> {
    let signer_public_key = proof.signer_public_key.as_ref().ok_or_else(|| {
        crate::Error::build_verification_error(
            "E_SIGNER_PUB_MISSING".to_string(),
            "Required signer_pub is missing from verified proof".to_string(),
        )
    })?;
    let signer_identity = build_signer_identity(signer_public_key)?;
    let judgment = judge_signer_trust_with_additional(
        &signer_identity,
        &trust_ctx.active_member_snapshot(),
        &AdditionalKnownKeyCache::new(&trust_ctx.known_keys, &[]),
        &trust_ctx.self_trust,
    )?;
    enforce_signer_trust(
        trust_ctx,
        &judgment,
        signer_public_key,
        capability,
        current_recipients,
    )
}

pub(crate) fn push_signature_verification_warnings(
    warnings: &mut Vec<String>,
    proof: &SignatureVerificationProof,
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<()> {
    let suppress_local_signer_expiry = matches_local_signer_identity(proof, local_key_identity)?;
    for warning in &proof.warnings {
        if suppress_local_signer_expiry && is_signer_key_expiry_warning(warning) {
            continue;
        }
        push_unique_warning(warnings, warning.clone());
    }
    Ok(())
}

pub fn evaluate_output_recipient_set_trust(
    trust_ctx: &TrustContext,
    recipient_set: &ArtifactRecipientSet,
    capability: CommandCapability,
) -> Result<ArtifactRecipientTrustOutcome> {
    let outcome = enforce_artifact_recipient_set_trust(trust_ctx, recipient_set, capability)?;
    debug!(
        "[TRUST] output recipient set: capability={}, recipient_count={}, outcome={}",
        capability.label(),
        recipient_set.recipient_kids().len(),
        describe_artifact_recipient_outcome(&outcome)
    );
    Ok(outcome)
}

fn matches_local_signer_identity(
    proof: &SignatureVerificationProof,
    local_key_identity: Option<&LocalKeyIdentity>,
) -> Result<bool> {
    let (Some(identity), Some(signer_public_key)) = (local_key_identity, &proof.signer_public_key)
    else {
        return Ok(false);
    };
    identity.matches_public_key(signer_public_key)
}

fn is_signer_key_expiry_warning(warning: &str) -> bool {
    warning.starts_with("Artifact signing key expires in ")
        || warning.starts_with("Artifact signing key has expired.")
        || warning.starts_with("PublicKey for ")
}

pub fn enforce_policy_strict_key_checking<P>(
    strict_key_checking: crate::config::types::StrictKeyCheckingResolution,
) -> Result<()>
where
    P: TrustPolicy,
{
    if !P::CAPABILITY.allows_strict_key_checking_no() && strict_key_checking.is_disabled() {
        return Err(crate::Error::build_invalid_operation_error(format!(
            "SECRETENV_STRICT_KEY_CHECKING=no is not allowed for {}",
            P::CAPABILITY.label()
        )));
    }
    Ok(())
}

fn describe_artifact_recipient_outcome(outcome: &ArtifactRecipientTrustOutcome) -> &'static str {
    match outcome {
        ArtifactRecipientTrustOutcome::Accepted => "accepted",
        ArtifactRecipientTrustOutcome::SkippedStrictKeyCheckingNo => {
            "skipped-strict-key-checking-no"
        }
        ArtifactRecipientTrustOutcome::NeedsManualApproval(_) => "needs-manual-approval",
    }
}

pub fn derive_self_sig_x(signing_key: &ed25519_dalek::SigningKey) -> [u8; 32] {
    let verifying_key: ed25519_dalek::VerifyingKey = signing_key.into();
    verifying_key.to_bytes()
}
