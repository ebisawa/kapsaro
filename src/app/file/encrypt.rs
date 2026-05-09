// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::artifact::file_content_recipient_evidence;
use crate::app::context::execution::{
    build_write_execution_warnings, resolve_write_execution, ExecutionContext,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::trust::review::{
    review_generated_artifact_recipient_set, GeneratedArtifactRecipientSetReview,
    TrustExecutionContext,
};
use crate::app::trust::{
    derive_self_sig_x, ArtifactRecipientTrustOutcome, CommandCapability, EncryptPolicy,
    RecipientTrustOutcome, TrustContext, WriteRecipientTrustPlan,
};
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::encrypt::encrypt_file_content;
use crate::feature::envelope::signature::build_signing_context;
#[cfg(test)]
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::format::content::FileEncContent;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::model::public_key::VerifiedRecipientKey;
use crate::{Error, Result};

pub(crate) struct EncryptFileCommand {
    pub execution: ExecutionContext,
    pub warnings: Vec<String>,
    input_bytes: Vec<u8>,
    member_handles: Vec<String>,
    verified_keys: Vec<VerifiedRecipientKey>,
    pub recipient_trust: RecipientTrustOutcome,
    trust_context: TrustContext,
}

pub(crate) fn resolve_encrypt_file_command(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    input_bytes: Vec<u8>,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<EncryptFileCommand> {
    let execution = resolve_encrypt_execution(options, member_handle, ssh_ctx)?;
    let workspace_root = require_encrypt_workspace(&execution)?;
    let trust_plan = WriteRecipientTrustPlan::<EncryptPolicy>::load(
        options,
        &workspace_root.root_path,
        &execution.member_handle,
        Some(derive_self_sig_x(&execution.key_ctx.signing_key)),
        options.debug,
    )?;
    let workspace_members = trust_plan.workspace_members();
    let mut warnings = build_write_execution_warnings(&execution)?;
    warnings.extend(trust_plan.warnings().iter().cloned());

    Ok(EncryptFileCommand {
        execution,
        warnings,
        input_bytes,
        member_handles: workspace_members.member_handles().to_vec(),
        verified_keys: workspace_members.verified_recipients().to_vec(),
        recipient_trust: trust_plan.recipient_trust().clone(),
        trust_context: trust_plan.trust_context().clone(),
    })
}

pub(crate) fn execute_encrypt_file_command(
    command: &EncryptFileCommand,
    debug: bool,
) -> Result<String> {
    let signing = build_signing_context(&command.execution.key_ctx, debug)?;
    encrypt_file_content(
        &command.input_bytes,
        &command.member_handles,
        &command.verified_keys,
        &signing,
    )
}

pub(crate) fn execute_encrypt_file_command_with_recipient_set_confirmation<ConfirmRecipientSet>(
    options: &CommonCommandOptions,
    command: &EncryptFileCommand,
    debug: bool,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<(String, Vec<String>)>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let encrypted = execute_encrypt_file_command(command, debug)?;
    let content = FileEncContent::new_unchecked(encrypted.clone());
    let evidence = file_content_recipient_evidence(&content)?;
    let mut warnings = Vec::new();
    review_generated_artifact_recipient_set(
        TrustExecutionContext {
            options,
            execution: &command.execution,
            warnings: &[],
        },
        GeneratedArtifactRecipientSetReview {
            trust_ctx: &command.trust_context,
            signer_kid: command.execution.key_ctx.kid.as_str(),
            recipient_set: &evidence.recipient_set,
            capability: CommandCapability::Encrypt,
            context_label: "encrypt output member set",
        },
        &mut |new_warnings| warnings.extend_from_slice(new_warnings),
        confirm_recipient_set,
    )?;
    Ok((encrypted, warnings))
}

#[cfg(test)]
pub(crate) fn evaluate_encrypt_output_recipient_set(
    command: &EncryptFileCommand,
    recipient_set: &ArtifactRecipientSet,
) -> Result<ArtifactRecipientTrustOutcome> {
    crate::app::trust::evaluate_output_recipient_set_trust(
        &command.trust_context,
        command.execution.key_ctx.kid.as_str(),
        recipient_set,
        CommandCapability::Encrypt,
    )
}

fn resolve_encrypt_execution(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<ExecutionContext> {
    let execution = resolve_write_execution(options, member_handle, ssh_ctx)?;
    enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
    Ok(execution)
}

fn require_encrypt_workspace(execution: &ExecutionContext) -> Result<WorkspaceRoot> {
    execution
        .workspace_root
        .clone()
        .ok_or_else(|| Error::Config {
            message: "Workspace is required for encrypt".to_string(),
        })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_file_encrypt_test.rs"]
mod tests;
