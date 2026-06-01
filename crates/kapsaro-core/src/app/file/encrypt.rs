// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::{
    build_write_execution_warnings, resolve_write_execution, ExecutionContext,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::trust::review::{
    review_artifact_output_recipient_set, ArtifactOutputRecipientSetReviewInput,
};
use crate::app::trust::{
    ArtifactRecipientTrustOutcome, CommandCapability, EncryptPolicy, RecipientTrustOutcome,
    TrustContext, WriteRecipientTrustPlan,
};
use crate::feature::context::crypto::build_signing_context;
use crate::feature::encrypt::encrypt_file_content;
#[cfg(test)]
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::format::content::{EncContent, FileEncContent};
use crate::io::workspace::detection::WorkspaceRoot;
use crate::model::public_key::VerifiedRecipientKey;
use crate::{Error, Result};

pub struct EncryptFileCommand {
    pub execution: ExecutionContext,
    pub warnings: Vec<String>,
    input_bytes: Vec<u8>,
    member_handles: Vec<String>,
    verified_keys: Vec<VerifiedRecipientKey>,
    pub recipient_trust: RecipientTrustOutcome,
    trust_context: TrustContext,
}

pub fn resolve_encrypt_file_command(
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
        Some(execution.key_ctx.self_signature_public_key_x()),
        Some(execution.key_ctx.local_key_identity()),
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

pub fn execute_encrypt_file_command(command: &EncryptFileCommand, debug: bool) -> Result<String> {
    let signing = build_signing_context(&command.execution.key_ctx, debug)?;
    encrypt_file_content(
        &command.input_bytes,
        &command.member_handles,
        &command.verified_keys,
        &signing,
    )
}

pub fn execute_encrypt_file_command_with_recipient_set_confirmation<ConfirmRecipientSet>(
    options: &CommonCommandOptions,
    command: &EncryptFileCommand,
    debug: bool,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<(String, Vec<String>)>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let encrypted = execute_encrypt_file_command(command, debug)?;
    let content = EncContent::FileEnc(FileEncContent::new_unchecked(encrypted.clone()));
    let mut warnings = Vec::new();
    review_artifact_output_recipient_set(
        ArtifactOutputRecipientSetReviewInput {
            options,
            execution: &command.execution,
            trust_ctx: &command.trust_context,
            content: &content,
            capability: CommandCapability::Encrypt,
            context_label: "encrypt output member set",
        },
        &mut warnings,
        confirm_recipient_set,
    )?;
    Ok((encrypted, warnings))
}

#[cfg(test)]
pub fn evaluate_encrypt_output_recipient_set(
    command: &EncryptFileCommand,
    recipient_set: &ArtifactRecipientSet,
) -> Result<ArtifactRecipientTrustOutcome> {
    crate::app::trust::evaluate_output_recipient_set_trust(
        &command.trust_context,
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
    execution.key_ctx.enforce_signing_key_not_expired()?;
    Ok(execution)
}

fn require_encrypt_workspace(execution: &ExecutionContext) -> Result<WorkspaceRoot> {
    execution
        .workspace_root
        .clone()
        .ok_or_else(|| Error::build_config_error("Workspace is required for encrypt".to_string()))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_file_encrypt_test.rs"]
mod tests;
