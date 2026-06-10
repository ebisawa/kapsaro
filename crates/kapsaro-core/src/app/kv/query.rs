// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::evaluate_selected_decryption_key_expiry;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::errors::build_kv_key_not_found_error;
use crate::app::trust::{
    evaluate_read_artifact_trust, push_signature_verification_warnings, ReadTrustPolicy,
    RecipientTrustOutcome, SignerTrustOutcome,
};
use crate::feature::envelope::key_possession::verify_kv_key_possession;
use crate::feature::envelope::unwrap::unwrap_master_key_for_kv_with_context;
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::kv::decrypt::{
    decrypt_kv_document_with_context, decrypt_kv_single_entry_with_context,
};
use crate::feature::kv::query::{
    decode_decrypted_kv_value, decode_decrypted_kv_values, list_kv_keys_with_disclosed,
};
use crate::feature::trust::recipient_sets::kv_recipient_evidence;
use crate::feature::verify::kv::signature::verify_kv_content_for_operation;
use crate::support::secret::SecretEnvironmentMap;
use crate::support::warning::push_unique_warning;
use crate::Result;
use tracing::debug;

use super::session::KvCommandSession;
use super::types::{KvDisclosedEntry, KvReadMode, KvReadResult};
use crate::app::context::execution::SelectedDecryptionKeyExpiry;
use crate::app::trust::evaluation::ReadArtifactTrustPlan;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;

pub struct KvReadCommand {
    pub execution: crate::app::context::execution::ExecutionContext,
    verified_doc: crate::model::kv_enc::verified::VerifiedKvEncDocument,
    disclosed: Vec<KvDisclosedEntry>,
    pub trust_outcome: SignerTrustOutcome,
    pub recipient_trust_outcome: RecipientTrustOutcome,
    pub warnings: Vec<String>,
    target_path: std::path::PathBuf,
}

pub fn resolve_kv_read_command<P>(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    file_name: Option<&str>,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<KvReadCommand>
where
    P: ReadTrustPolicy,
{
    let command = KvCommandSession::resolve_read(options, member_handle, file_name, ssh_ctx)?;
    let file = command.load_required_file()?;
    let kv_content = file.kv_content();
    let operation_options = options.operation_options();
    let disclosed = collect_kv_disclosed_entries(&kv_content)?;
    let verified_doc = verify_kv_read_content(&kv_content, operation_options)?;
    let selected_key_expiry =
        evaluate_kv_read_key_expiry(&command.execution, &verified_doc, operation_options)?;
    let trust_plan = evaluate_kv_read_trust::<P>(options, &command.execution, &verified_doc)?;
    let warnings = collect_kv_read_warnings(
        command.warnings,
        verified_doc.proof(),
        selected_key_expiry,
        trust_plan.warnings,
    )?;

    Ok(KvReadCommand {
        execution: command.execution,
        verified_doc,
        disclosed,
        trust_outcome: trust_plan.signer_outcome,
        recipient_trust_outcome: trust_plan.recipient_outcome,
        warnings,
        target_path: file.target.file_path,
    })
}

fn collect_kv_disclosed_entries(
    kv_content: &crate::format::content::KvEncContent,
) -> Result<Vec<KvDisclosedEntry>> {
    Ok(list_kv_keys_with_disclosed(kv_content)?
        .into_iter()
        .map(Into::into)
        .collect())
}

fn verify_kv_read_content(
    kv_content: &crate::format::content::KvEncContent,
    options: crate::api::operation::OperationOptions,
) -> Result<VerifiedKvEncDocument> {
    verify_kv_content_for_operation(kv_content, options.debug(), options.allow_expired_key())
}

fn evaluate_kv_read_key_expiry(
    execution: &crate::app::context::execution::ExecutionContext,
    verified_doc: &VerifiedKvEncDocument,
    options: crate::api::operation::OperationOptions,
) -> Result<SelectedDecryptionKeyExpiry> {
    let wrap_set = WrapSet::parse(&verified_doc.document().wrap().wrap, "Document")?;
    evaluate_selected_decryption_key_expiry(
        execution,
        &wrap_set,
        options.allow_expired_key(),
        options.debug(),
    )
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

pub fn execute_kv_list_command(
    command: &KvReadCommand,
    debug_enabled: bool,
) -> Result<Vec<KvDisclosedEntry>> {
    let doc = command.verified_doc.document();
    let master_key = unwrap_master_key_for_kv_with_context(
        &doc.head().sid,
        &doc.wrap().wrap,
        &command.execution.member_handle,
        &command.execution.key_ctx,
        debug_enabled,
    )?;
    verify_kv_key_possession(&command.verified_doc, master_key.value, debug_enabled)?;
    Ok(command.disclosed.clone())
}

pub fn execute_kv_read_command(
    command: &KvReadCommand,
    mode: KvReadMode<'_>,
    debug: bool,
) -> Result<KvReadResult> {
    let values = match mode {
        KvReadMode::All => decode_decrypted_kv_values(
            decrypt_kv_document_with_context(
                &command.verified_doc,
                &command.execution.member_handle,
                &command.execution.key_ctx,
                debug,
            )?
            .value,
        )?,
        KvReadMode::Single(key) => {
            let value = decrypt_kv_single_entry_with_context(
                &command.verified_doc,
                &command.execution.member_handle,
                &command.execution.key_ctx,
                key,
                debug,
            )
            .map(|result| result.value)
            .map_err(|e| build_kv_key_not_found_error(e, &command.target_path, key))?;
            let value = decode_decrypted_kv_value(key, value)?;
            std::collections::BTreeMap::from([(key.to_string(), value)])
        }
    };

    Ok(KvReadResult {
        values,
        disclosed: command.disclosed.clone(),
    })
}

pub fn execute_kv_env_command(
    command: &KvReadCommand,
    debug_enabled: bool,
) -> Result<SecretEnvironmentMap> {
    if debug_enabled {
        debug!("[KV] env command: decrypt values");
    }
    decode_decrypted_kv_values(
        decrypt_kv_document_with_context(
            &command.verified_doc,
            &command.execution.member_handle,
            &command.execution.key_ctx,
            debug_enabled,
        )?
        .value,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_kv_query_test.rs"]
mod tests;
