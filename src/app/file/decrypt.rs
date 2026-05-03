// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::app::context::execution::{
    build_read_execution_warnings, resolve_read_execution, ExecutionContext,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::trust::{evaluate_read_signer_trust, DecryptPolicy, SignerTrustOutcome};
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::verify::file::verify_file_content;
use crate::format::content::FileEncContent;
use crate::Result;

pub(crate) struct DecryptFileCommand {
    pub execution: ExecutionContext,
    pub verified_doc: crate::model::file_enc::VerifiedFileEncDocument,
    pub trust_outcome: SignerTrustOutcome,
    pub warnings: Vec<String>,
    verbose: bool,
}

pub(crate) fn resolve_decrypt_file_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    kid: Option<&str>,
    content: FileEncContent,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<DecryptFileCommand> {
    let execution = resolve_read_execution(options, member_handle, kid, ssh_ctx)?;
    let mut warnings = build_read_execution_warnings(&execution)?;

    let verified_doc = verify_file_content(&content, options.verbose)?;

    let trust_plan =
        evaluate_read_signer_trust::<DecryptPolicy>(options, &execution, &verified_doc.proof)?;
    warnings.extend(trust_plan.warnings);

    Ok(DecryptFileCommand {
        execution,
        verified_doc,
        trust_outcome: trust_plan.outcome,
        warnings,
        verbose: options.verbose,
    })
}

pub(crate) fn execute_decrypt_file_command(
    command: &DecryptFileCommand,
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_file_document_with_context(
        &command.verified_doc,
        &command.execution.member_handle,
        &command.execution.key_ctx,
        command.verbose,
    )
    .map(|result| result.value)
}
