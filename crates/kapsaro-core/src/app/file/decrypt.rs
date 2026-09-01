// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust evaluation for the file decrypt command.
//! Builds the plan a decrypt runs under and reports the key it selected.

use crate::app::context::execution::{
    evaluate_selected_decryption_key_expiry, ExecutionContext, SelectedDecryptionKeyExpiry,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::evaluation::ReadArtifactTrustPlan;
use crate::app::trust::evaluation::{
    build_read_artifact_trust_plan, known_key_review, resolve_read_trust_context_for_policy,
};
use crate::app::trust::{push_signature_verification_warnings, DecryptPolicy};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::service::file::VerifiedFileEncArtifact;
use crate::service::operation::OperationOptions;
use crate::support::warning::push_unique_warning;
use crate::Result;

pub fn evaluate_decrypt_file_trust_plan(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    verified_artifact: &VerifiedFileEncArtifact,
) -> Result<ReadArtifactTrustPlan> {
    let operation_options = options.operation_options();
    let verified_doc = verified_artifact.inner();
    let selected_key_expiry =
        evaluate_decrypt_file_key_expiry(execution, verified_doc, operation_options)?;
    let trust_plan = evaluate_decrypt_file_trust(options, execution, verified_artifact)?;
    let warnings = collect_decrypt_file_warnings(
        verified_doc.proof(),
        selected_key_expiry,
        trust_plan.warnings,
    )?;

    Ok(ReadArtifactTrustPlan {
        signer_outcome: trust_plan.signer_outcome,
        recipient_outcome: trust_plan.recipient_outcome,
        known_key_review: trust_plan.known_key_review,
        warnings,
    })
}

fn evaluate_decrypt_file_key_expiry(
    execution: &ExecutionContext,
    verified_doc: &VerifiedFileEncDocument,
    options: OperationOptions,
) -> Result<SelectedDecryptionKeyExpiry> {
    let wrap_set = WrapSet::parse(&verified_doc.document().protected.wrap, "Document")?;
    evaluate_selected_decryption_key_expiry(execution, &wrap_set, options.allow_expired_key())
}

fn evaluate_decrypt_file_trust(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    verified_artifact: &VerifiedFileEncArtifact,
) -> Result<ReadArtifactTrustPlan> {
    let loaded = resolve_read_trust_context_for_policy::<DecryptPolicy>(options, execution)?;
    let review = known_key_review(&loaded.trust_ctx);
    let decision = loaded.evaluator.preflight_file_read(
        verified_artifact,
        &execution.key_ctx,
        review,
        options.allow_non_member,
    )?;
    build_read_artifact_trust_plan(
        decision,
        verified_artifact.inner().proof(),
        review,
        loaded.trust_ctx.is_interactive,
        loaded.warnings,
    )
}

fn collect_decrypt_file_warnings(
    proof: &crate::model::verification::SignatureVerificationProof,
    selected_key_expiry: SelectedDecryptionKeyExpiry,
    trust_warnings: Vec<String>,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    push_signature_verification_warnings(
        &mut warnings,
        proof,
        Some(&selected_key_expiry.key_identity),
    )?;
    if let Some(warning) = selected_key_expiry.warning {
        push_unique_warning(&mut warnings, warning);
    }
    for warning in trust_warnings {
        push_unique_warning(&mut warnings, warning);
    }
    Ok(warnings)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_file_decrypt_test.rs"]
mod tests;
