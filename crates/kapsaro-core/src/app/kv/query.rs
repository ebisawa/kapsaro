// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read-path orchestration for the KV query commands.
//! Resolves which document to read and the trust plan that read runs under.

use crate::app::context::execution::evaluate_selected_decryption_key_expiry;
use crate::app::context::options::CommonCommandOptions;
use crate::app::errors::build_default_kv_file_not_found_error;
use crate::app::trust::evaluation::{
    build_read_artifact_trust_plan, known_key_review, resolve_read_trust_context_for_policy,
};
use crate::app::trust::{push_signature_verification_warnings, ReadTrustPolicy};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::service::kv::{KvEncArtifact, VerifiedKvEncArtifact};
use crate::support::fs::relative::file_exists_at;
use crate::support::warning::push_unique_warning;
use crate::{ErrorKind, Result};

use super::session::KvFileTarget;
use crate::app::context::execution::SelectedDecryptionKeyExpiry;
use crate::app::trust::evaluation::ReadArtifactTrustPlan;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;

/// One KV input read through the workspace capability a command fixed.
pub struct KvReadInput {
    pub file_path: std::path::PathBuf,
    pub file_name: String,
    pub artifact: KvEncArtifact,
}

/// Load a KV artifact from the secrets directory fixed by `execution`.
pub fn load_kv_read_input(
    execution: &crate::app::context::execution::ExecutionContext,
    file_name: Option<&str>,
) -> Result<KvReadInput> {
    let target = KvFileTarget::bind(execution, file_name)?;
    let secrets_directory = execution.ensured_secrets_directory()?;
    let artifact =
        KvEncArtifact::load_at(secrets_directory.as_ref(), &target.file_name).map_err(|error| {
            let is_absent = matches!(
                file_exists_at(secrets_directory.as_ref(), &target.file_name),
                Ok(false)
            );
            if error.kind() == ErrorKind::NotFound || is_absent {
                return build_default_kv_file_not_found_error(&target.file_path);
            }
            error
        })?;
    Ok(KvReadInput {
        file_path: target.file_path,
        file_name: target.file_name,
        artifact,
    })
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
    let trust_plan = evaluate_kv_read_trust::<P>(options, execution, verified_artifact)?;
    let warnings = collect_kv_read_warnings(
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

fn evaluate_kv_read_key_expiry(
    execution: &crate::app::context::execution::ExecutionContext,
    verified_doc: &VerifiedKvEncDocument,
    options: crate::service::operation::OperationOptions,
) -> Result<SelectedDecryptionKeyExpiry> {
    let wrap_set = WrapSet::parse(&verified_doc.document().wrap().wrap, "Document")?;
    evaluate_selected_decryption_key_expiry(execution, &wrap_set, options.allow_expired_key())
}

fn evaluate_kv_read_trust<P>(
    options: &CommonCommandOptions,
    execution: &crate::app::context::execution::ExecutionContext,
    verified_artifact: &VerifiedKvEncArtifact,
) -> Result<ReadArtifactTrustPlan>
where
    P: ReadTrustPolicy,
{
    let loaded = resolve_read_trust_context_for_policy::<P>(options, execution)?;
    let review = known_key_review(&loaded.trust_ctx);
    let decision = loaded.evaluator.preflight_kv_read(
        verified_artifact,
        &execution.key_ctx,
        review,
        options.allow_non_member && P::CAPABILITY.allows_non_member_acceptance(),
    )?;
    build_read_artifact_trust_plan(
        decision,
        verified_artifact.inner().proof(),
        review,
        loaded.trust_ctx.is_interactive,
        loaded.warnings,
    )
}

fn collect_kv_read_warnings(
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
#[path = "../../../tests/unit/internal/app_kv_query_test.rs"]
mod tests;
