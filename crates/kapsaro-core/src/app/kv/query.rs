// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::api::kv::VerifiedKvEncArtifact;
use crate::app::context::execution::evaluate_selected_decryption_key_expiry;
use crate::app::context::options::CommonCommandOptions;
use crate::app::errors::build_default_kv_file_not_found_error;
use crate::app::trust::{
    evaluate_read_artifact_trust, push_signature_verification_warnings, ReadTrustPolicy,
    RecipientTrustOutcome, SignerTrustOutcome,
};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::trust::recipient_sets::kv_recipient_evidence;
use crate::support::warning::push_unique_warning;
use crate::Result;

use super::session::KvFileTarget;
use crate::app::context::execution::SelectedDecryptionKeyExpiry;
use crate::app::trust::evaluation::ReadArtifactTrustPlan;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;

pub fn resolve_kv_read_path(
    options: &CommonCommandOptions,
    file_name: Option<&str>,
) -> Result<std::path::PathBuf> {
    let target = KvFileTarget::resolve(options, file_name)?;
    if !target.file_path.exists() {
        return Err(build_default_kv_file_not_found_error(&target.file_path));
    }
    Ok(target.file_path)
}

pub fn evaluate_kv_read_trust_plan<P>(
    options: &CommonCommandOptions,
    execution: &crate::app::context::execution::ExecutionContext,
    verified_artifact: &VerifiedKvEncArtifact,
) -> Result<ReadArtifactTrustPlan>
where
    P: ReadTrustPolicy,
{
    let operation_options = options.operation_options();
    let verified_doc = verified_artifact.inner();
    let selected_key_expiry =
        evaluate_kv_read_key_expiry(execution, verified_doc, operation_options)?;
    let trust_plan = evaluate_kv_read_trust::<P>(options, execution, verified_doc)?;
    let warnings = collect_kv_read_warnings(
        Vec::new(),
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

fn evaluate_kv_read_key_expiry(
    execution: &crate::app::context::execution::ExecutionContext,
    verified_doc: &VerifiedKvEncDocument,
    options: crate::api::operation::OperationOptions,
) -> Result<SelectedDecryptionKeyExpiry> {
    let wrap_set = WrapSet::parse(&verified_doc.document().wrap().wrap, "Document")?;
    evaluate_selected_decryption_key_expiry(execution, &wrap_set, options.allow_expired_key())
}

fn evaluate_kv_read_trust<P>(
    options: &CommonCommandOptions,
    execution: &crate::app::context::execution::ExecutionContext,
    verified_doc: &VerifiedKvEncDocument,
) -> Result<ReadArtifactTrustPlan>
where
    P: ReadTrustPolicy,
{
    let recipient_evidence = kv_recipient_evidence(verified_doc.document())?;
    evaluate_read_artifact_trust::<P>(
        options,
        execution,
        verified_doc.proof(),
        &recipient_evidence.recipient_set,
        &recipient_evidence.recipient_handles,
    )
}

fn collect_kv_read_warnings(
    mut warnings: Vec<String>,
    proof: &crate::model::verification::SignatureVerificationProof,
    selected_key_expiry: SelectedDecryptionKeyExpiry,
    trust_warnings: Vec<String>,
) -> Result<Vec<String>> {
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
#[path = "../../../tests/unit/internal/app_kv_query_test.rs"]
mod tests;
