// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust evaluation for the file decrypt command.
//! Builds the plan a decrypt runs under and reports the key it selected.

use crate::api::file::VerifiedFileEncArtifact;
use crate::app::context::execution::{
    evaluate_selected_decryption_key_expiry, ExecutionContext, SelectedDecryptionKeyExpiry,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::evaluation::ReadArtifactTrustPlan;
use crate::app::trust::{
    evaluate_read_artifact_trust, push_signature_verification_warnings, DecryptPolicy,
};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::trust::recipient_sets::file_recipient_evidence;
use crate::support::warning::push_unique_warning;
use crate::Result;
use crate::{api::operation::OperationOptions, model::file_enc::VerifiedFileEncDocument};

pub fn evaluate_decrypt_file_trust_plan(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    verified_artifact: &VerifiedFileEncArtifact,
) -> Result<ReadArtifactTrustPlan> {
    let operation_options = options.operation_options();
    let verified_doc = verified_artifact.inner();
    let selected_key_expiry =
        evaluate_decrypt_file_key_expiry(execution, verified_doc, operation_options)?;
    let trust_plan = evaluate_decrypt_file_trust(options, execution, verified_doc)?;
    let warnings = collect_decrypt_file_warnings(
        verified_doc.proof(),
        selected_key_expiry,
        trust_plan.warnings,
    )?;

    Ok(ReadArtifactTrustPlan {
        signer_outcome: trust_plan.signer_outcome,
        recipient_outcome: trust_plan.recipient_outcome,
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
    verified_doc: &VerifiedFileEncDocument,
) -> Result<ReadArtifactTrustPlan> {
    let recipient_evidence = file_recipient_evidence(verified_doc.document())?;
    evaluate_read_artifact_trust::<DecryptPolicy>(
        options,
        execution,
        verified_doc.proof(),
        &recipient_evidence.recipient_set,
        &recipient_evidence.recipient_handles,
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
