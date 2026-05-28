// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::app::context::execution::{
    evaluate_selected_decryption_key_expiry, resolve_read_execution, ExecutionContext,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::trust::{
    evaluate_read_artifact_trust, push_signature_verification_warnings, DecryptPolicy,
    RecipientTrustOutcome, SignerTrustOutcome,
};
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::trust::recipient_sets::file_recipient_evidence;
use crate::feature::verify::file::verify_file_content_for_operation;
use crate::format::content::FileEncContent;
use crate::support::warning::push_unique_warning;
use crate::Result;

pub struct DecryptFileCommand {
    pub execution: ExecutionContext,
    pub verified_doc: crate::model::file_enc::VerifiedFileEncDocument,
    pub trust_outcome: SignerTrustOutcome,
    pub recipient_trust_outcome: RecipientTrustOutcome,
    pub warnings: Vec<String>,
    debug: bool,
}

pub fn resolve_decrypt_file_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    kid: Option<&str>,
    content: String,
    source_name: impl Into<String>,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<DecryptFileCommand> {
    let execution = resolve_read_execution(options, member_handle, kid, ssh_ctx)?;
    let mut warnings = Vec::new();
    let content = FileEncContent::detect_with_source(content, source_name)?;
    let operation_options = options.operation_options();

    let verified_doc = verify_file_content_for_operation(
        &content,
        operation_options.debug(),
        operation_options.allow_expired_key(),
    )?;
    let wrap_set = WrapSet::parse(&verified_doc.document().protected.wrap, "Document")?;
    let selected_key_expiry = evaluate_selected_decryption_key_expiry(
        &execution,
        &wrap_set,
        operation_options.allow_expired_key(),
        operation_options.debug(),
    )?;
    push_signature_verification_warnings(
        &mut warnings,
        verified_doc.proof(),
        Some(&selected_key_expiry.key_identity),
    )?;
    if let Some(warning) = selected_key_expiry.warning {
        push_unique_warning(&mut warnings, warning);
    }
    let recipient_evidence = file_recipient_evidence(verified_doc.document())?;

    let trust_plan = evaluate_read_artifact_trust::<DecryptPolicy>(
        options,
        &execution,
        verified_doc.proof(),
        &recipient_evidence.recipient_set,
        &recipient_evidence.recipient_handles,
    )?;
    for warning in trust_plan.warnings {
        push_unique_warning(&mut warnings, warning);
    }

    Ok(DecryptFileCommand {
        execution,
        verified_doc,
        trust_outcome: trust_plan.signer_outcome,
        recipient_trust_outcome: trust_plan.recipient_outcome,
        warnings,
        debug: operation_options.debug(),
    })
}

pub fn validate_decrypt_file_input(content: &str, source_name: impl Into<String>) -> Result<()> {
    FileEncContent::detect_with_source(content.to_string(), source_name).map(|_| ())
}

pub fn execute_decrypt_file_command(command: &DecryptFileCommand) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_file_document_with_context(
        &command.verified_doc,
        &command.execution.member_handle,
        &command.execution.key_ctx,
        command.debug,
    )
    .map(|result| result.value)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_file_decrypt_test.rs"]
mod tests;
