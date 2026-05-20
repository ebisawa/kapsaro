// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::artifact::kv_recipient_evidence;
use crate::app::context::execution::enforce_selected_decryption_key_expiry;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::errors::build_kv_key_not_found_error;
use crate::app::trust::{
    evaluate_read_artifact_trust, ReadTrustPolicy, RecipientTrustOutcome, SignerTrustOutcome,
};
use crate::feature::kv::decrypt::{
    decrypt_kv_document_with_context, decrypt_kv_single_entry_with_context,
};
use crate::feature::kv::query::{
    decode_decrypted_kv_value, decode_decrypted_kv_values, list_kv_keys_with_disclosed,
    KvDisclosedEntry,
};
use crate::feature::verify::kv::signature::verify_kv_content_for_operation;
use crate::model::common::WrapSet;
use crate::support::secret::SecretEnvMap;
use crate::Result;

use super::session::{KvCommandSession, KvFileSession};
use super::types::{KvReadMode, KvReadResult};

pub struct KvReadCommand {
    pub execution: crate::app::context::execution::ExecutionContext,
    verified_doc: crate::model::kv_enc::verified::VerifiedKvEncDocument,
    disclosed: Vec<KvDisclosedEntry>,
    pub trust_outcome: SignerTrustOutcome,
    pub recipient_trust_outcome: RecipientTrustOutcome,
    pub warnings: Vec<String>,
    target_path: std::path::PathBuf,
}

pub fn list_kv_command(
    options: &CommonCommandOptions,
    file_name: Option<&str>,
) -> Result<Vec<KvDisclosedEntry>> {
    let session = KvFileSession::load(options, file_name)?;
    list_kv_keys_with_disclosed(&session.kv_content())
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
    let mut command = KvCommandSession::resolve_read(options, member_handle, file_name, ssh_ctx)?;
    let file = command.load_required_file()?;
    let disclosed = list_kv_keys_with_disclosed(&file.kv_content())?;
    let verified_doc = verify_kv_content_for_operation(
        &file.kv_content(),
        options.debug,
        options.allow_expired_key,
    )?;
    for warning in &verified_doc.proof().warnings {
        push_unique_warning(&mut command.warnings, warning.clone());
    }
    let wrap_set = WrapSet::parse(&verified_doc.document().wrap().wrap, "Document")?;
    if let Some(warning) = enforce_selected_decryption_key_expiry(
        &command.execution,
        &wrap_set,
        options.allow_expired_key,
        options.debug,
    )? {
        push_unique_warning(&mut command.warnings, warning);
    }
    let recipient_evidence = kv_recipient_evidence(verified_doc.document())?;
    let trust_plan = evaluate_read_artifact_trust::<P>(
        options,
        &command.execution,
        verified_doc.proof(),
        &recipient_evidence.recipient_set,
        &recipient_evidence.recipient_handles,
    )?;
    let mut warnings = command.warnings;
    warnings.extend(trust_plan.warnings);

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

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
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

pub fn execute_kv_env_command(command: &KvReadCommand) -> Result<SecretEnvMap> {
    decode_decrypted_kv_values(
        decrypt_kv_document_with_context(
            &command.verified_doc,
            &command.execution.member_handle,
            &command.execution.key_ctx,
            false,
        )?
        .value,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_kv_query_test.rs"]
mod tests;
