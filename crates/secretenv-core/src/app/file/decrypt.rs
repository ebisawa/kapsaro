// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::app::artifact::file_recipient_evidence;
use crate::app::context::execution::{
    enforce_selected_decryption_key_expiry, resolve_read_execution, ExecutionContext,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::trust::{
    evaluate_read_artifact_trust, DecryptPolicy, RecipientTrustOutcome, SignerTrustOutcome,
};
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::verify::file::verify_file_content_for_operation;
use crate::format::content::FileEncContent;
use crate::model::common::WrapSet;
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
    content: FileEncContent,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<DecryptFileCommand> {
    let execution = resolve_read_execution(options, member_handle, kid, ssh_ctx)?;
    let mut warnings = Vec::new();

    let verified_doc =
        verify_file_content_for_operation(&content, options.debug, options.allow_expired_key)?;
    for warning in &verified_doc.proof.warnings {
        push_unique_warning(&mut warnings, warning.clone());
    }
    let wrap_set = WrapSet::parse(&verified_doc.document.protected.wrap, "Document")?;
    if let Some(warning) = enforce_selected_decryption_key_expiry(
        &execution,
        &wrap_set,
        options.allow_expired_key,
        options.debug,
    )? {
        push_unique_warning(&mut warnings, warning);
    }
    let recipient_evidence = file_recipient_evidence(&verified_doc.document)?;

    let trust_plan = evaluate_read_artifact_trust::<DecryptPolicy>(
        options,
        &execution,
        &verified_doc.proof,
        &recipient_evidence.recipient_set,
        &recipient_evidence.recipient_handles,
    )?;
    warnings.extend(trust_plan.warnings);

    Ok(DecryptFileCommand {
        execution,
        verified_doc,
        trust_outcome: trust_plan.signer_outcome,
        recipient_trust_outcome: trust_plan.recipient_outcome,
        warnings,
        debug: options.debug,
    })
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
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
