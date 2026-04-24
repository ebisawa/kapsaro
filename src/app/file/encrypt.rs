// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::{
    build_write_execution_warnings, resolve_write_execution, ExecutionContext,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::trust::{
    derive_self_sig_x, EncryptPolicy, RecipientTrustOutcome, WriteRecipientTrustPlan,
};
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::encrypt::encrypt_file_content;
use crate::feature::envelope::signature::build_signing_context;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::model::public_key::VerifiedRecipientKey;
use crate::{Error, Result};

pub(crate) struct EncryptFileCommand {
    pub execution: ExecutionContext,
    pub warnings: Vec<String>,
    input_bytes: Vec<u8>,
    member_ids: Vec<String>,
    verified_keys: Vec<VerifiedRecipientKey>,
    pub recipient_trust: RecipientTrustOutcome,
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
        &execution.member_id,
        Some(derive_self_sig_x(&execution.key_ctx.signing_key)),
        options.verbose,
    )?;
    let workspace_members = trust_plan.workspace_members();
    let mut warnings = build_write_execution_warnings(&execution)?;
    warnings.extend(trust_plan.warnings().iter().cloned());

    Ok(EncryptFileCommand {
        execution,
        warnings,
        input_bytes,
        member_ids: workspace_members.member_ids().to_vec(),
        verified_keys: workspace_members.verified_recipients().to_vec(),
        recipient_trust: trust_plan.recipient_trust().clone(),
    })
}

pub(crate) fn execute_encrypt_file_command(
    command: &EncryptFileCommand,
    debug: bool,
) -> Result<String> {
    let signing = build_signing_context(&command.execution.key_ctx, debug)?;
    encrypt_file_content(
        &command.input_bytes,
        &command.member_ids,
        &command.verified_keys,
        &signing,
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
