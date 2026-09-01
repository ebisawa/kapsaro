// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI-only read policy exceptions bound to one reviewed artifact and operation.
//! Re-evaluates current trust state before producing a trusted public facade.

use crate::app::trust::SignerTrustOutcome;
use crate::service::file::{FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact};
use crate::service::key::KeyContext;
use crate::service::kv::{KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact};
use crate::service::operation::OperationOptions;
use crate::service::trust::{
    KnownKeyReview, ReadTrustExceptions, TrustDecision, TrustPolicyEvaluator,
};
use crate::{Error, Result};

pub fn evaluate_file_after_cli_review<'a>(
    evaluator: &TrustPolicyEvaluator,
    reviewed: &VerifiedFileEncArtifact,
    current: &'a VerifiedFileEncArtifact,
    key_ctx: &'a KeyContext,
    signer_outcome: &SignerTrustOutcome,
    known_key_review: KnownKeyReview,
    options: OperationOptions,
) -> Result<TrustDecision<TrustedFileEncArtifact<'a>>> {
    let exceptions = build_exceptions(signer_outcome, known_key_review);
    enforce_exception_binding(
        reviewed.binding_digest()?,
        current.binding_digest()?,
        FileReadOperation::Decrypt,
    )?;
    evaluator.evaluate_file(
        current,
        key_ctx,
        FileReadOperation::Decrypt,
        options,
        exceptions,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_kv_after_cli_review<'a>(
    evaluator: &TrustPolicyEvaluator,
    reviewed: &VerifiedKvEncArtifact,
    current: &'a VerifiedKvEncArtifact,
    key_ctx: &'a KeyContext,
    operation: KvReadOperation,
    signer_outcome: &SignerTrustOutcome,
    known_key_review: KnownKeyReview,
    options: OperationOptions,
) -> Result<TrustDecision<TrustedKvEncArtifact<'a>>> {
    let exceptions = build_exceptions(signer_outcome, known_key_review);
    enforce_exception_binding(
        reviewed.binding_digest(),
        current.binding_digest(),
        &operation,
    )?;
    evaluator.evaluate_kv(current, key_ctx, operation, options, exceptions)
}

fn build_exceptions(
    signer_outcome: &SignerTrustOutcome,
    known_key_review: KnownKeyReview,
) -> ReadTrustExceptions {
    let exceptions = ReadTrustExceptions::none().with_known_key_review(known_key_review);
    match signer_outcome {
        SignerTrustOutcome::NeedsNonMemberAcceptance { candidate, .. } => exceptions
            .accepting_non_member(candidate.member_handle().clone(), candidate.kid().clone()),
        _ => exceptions,
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
