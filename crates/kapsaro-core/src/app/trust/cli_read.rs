// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI-only read policy exceptions bound to one reviewed artifact and operation.
//! Re-evaluates current trust state before producing a trusted public facade.

use crate::api::file::{FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact};
use crate::api::key::KeyContext;
use crate::api::kv::{KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact};
use crate::api::operation::OperationOptions;
use crate::api::trust::{CliReadTrustPolicy, TrustDecision, TrustPolicyEvaluator};
use crate::app::trust::SignerTrustOutcome;
use crate::config::resolution::strict_key_checking::resolve_strict_key_checking;
use crate::{Error, Result};

pub fn evaluate_file_after_cli_review<'a>(
    evaluator: &TrustPolicyEvaluator,
    reviewed: &VerifiedFileEncArtifact,
    current: &'a VerifiedFileEncArtifact,
    key_ctx: &'a KeyContext,
    signer_outcome: &SignerTrustOutcome,
    options: OperationOptions,
) -> Result<TrustDecision<TrustedFileEncArtifact<'a>>> {
    let policy = build_policy(signer_outcome);
    enforce_exception_binding(
        reviewed.binding_digest()?,
        current.binding_digest()?,
        FileReadOperation::Decrypt,
    )?;
    evaluator.evaluate_file_with_cli_policy(current, key_ctx, options, &policy)
}

pub fn evaluate_kv_after_cli_review<'a>(
    evaluator: &TrustPolicyEvaluator,
    reviewed: &VerifiedKvEncArtifact,
    current: &'a VerifiedKvEncArtifact,
    key_ctx: &'a KeyContext,
    operation: KvReadOperation,
    signer_outcome: &SignerTrustOutcome,
    options: OperationOptions,
) -> Result<TrustDecision<TrustedKvEncArtifact<'a>>> {
    let policy = build_policy(signer_outcome);
    enforce_exception_binding(
        reviewed.binding_digest(),
        current.binding_digest(),
        &operation,
    )?;
    evaluator.evaluate_kv_with_cli_policy(current, key_ctx, operation, options, &policy)
}

fn build_policy(signer_outcome: &SignerTrustOutcome) -> CliReadTrustPolicy {
    let accepted_non_member = match signer_outcome {
        SignerTrustOutcome::NeedsNonMemberAcceptance { candidate, .. } => Some((
            candidate.member_handle.to_string(),
            candidate.kid.to_string(),
        )),
        _ => None,
    };
    CliReadTrustPolicy {
        skip_known_key_review: resolve_strict_key_checking().is_disabled(),
        accepted_non_member,
    }
}

fn enforce_exception_binding(
    reviewed: [u8; 32],
    current: [u8; 32],
    operation: impl std::fmt::Debug,
) -> Result<()> {
    if reviewed != current {
        return Err(Error::build_verification_error(
            "E_TRUST_TARGET_CHANGED".to_string(),
            format!(
                "Reviewed artifact changed before {operation:?} authorization. Run the command again."
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_cli_read_test.rs"]
mod tests;
