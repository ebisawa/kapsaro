// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust evaluation helpers built on immutable command snapshots.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::enforcement::{
    build_signer_identity, enforce_signer_trust, SignerTrustOutcome,
};
use crate::app::trust::policy::{CommandCapability, ReadTrustPolicy, TrustPolicy};
use crate::app::trust::snapshot::{load_read_trust_context, TrustContext};
use crate::feature::trust::judgment::judge_signer_trust_with_additional;
use crate::feature::trust::judgment::AdditionalKnownKeyCache;
use crate::model::verification::SignatureVerificationProof;
use crate::Result;

pub(crate) struct ReadSignerTrustPlan {
    pub(crate) outcome: SignerTrustOutcome,
    pub(crate) warnings: Vec<String>,
}

pub(crate) fn evaluate_read_signer_trust<P>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    proof: &SignatureVerificationProof,
) -> Result<ReadSignerTrustPlan>
where
    P: ReadTrustPolicy,
{
    let workspace =
        execution
            .workspace_root
            .as_ref()
            .ok_or_else(|| crate::Error::InvalidOperation {
                message: format!(
                    "Workspace is required for {} trust evaluation",
                    P::CAPABILITY.label()
                ),
            })?;
    let loaded = load_read_trust_context(
        options,
        &workspace.root_path,
        &execution.member_id,
        Some(derive_self_sig_x(&execution.key_ctx.signing_key)),
        options.verbose,
    )?;
    let trust_ctx = &loaded.trust_ctx;
    let outcome = evaluate_signer_trust_with_proof(trust_ctx, proof, P::CAPABILITY, &[])?;
    Ok(ReadSignerTrustPlan {
        outcome,
        warnings: loaded.warnings,
    })
}

pub(crate) fn evaluate_signer_trust_with_proof(
    trust_ctx: &TrustContext,
    proof: &SignatureVerificationProof,
    capability: CommandCapability,
    current_recipients: &[String],
) -> Result<SignerTrustOutcome> {
    let signer_public_key =
        proof
            .signer_public_key
            .as_ref()
            .ok_or_else(|| crate::Error::Verify {
                rule: "E_SIGNER_PUB_MISSING".to_string(),
                message: "Required signer_pub is missing from verified proof".to_string(),
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

pub(crate) fn enforce_policy_strict_key_checking<P>(
    strict_key_checking: crate::config::types::StrictKeyCheckingResolution,
) -> Result<()>
where
    P: TrustPolicy,
{
    if !P::CAPABILITY.allows_strict_key_checking_no() && strict_key_checking.is_disabled() {
        return Err(crate::Error::InvalidOperation {
            message: format!(
                "SECRETENV_STRICT_KEY_CHECKING=no is not allowed for {}",
                P::CAPABILITY.label()
            ),
        });
    }
    Ok(())
}

pub(crate) fn derive_self_sig_x(signing_key: &ed25519_dalek::SigningKey) -> [u8; 32] {
    let verifying_key: ed25519_dalek::VerifyingKey = signing_key.into();
    verifying_key.to_bytes()
}
