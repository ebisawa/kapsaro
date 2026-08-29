// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File encryption use case.
//! Resolves recipients and workspace paths, then encrypts and signs one file.

use crate::app::context::execution::{build_write_execution_warnings, ExecutionContext};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::build_workspace_not_found_error;
use crate::app::context::review::{ensure_workspace_members_match_snapshot, ReviewedTrustStore};
use crate::app::trust::review::{
    review_artifact_output_recipient_set, ArtifactOutputRecipientSetReviewInput,
};
use crate::app::trust::{
    ArtifactRecipientTrustOutcome, CommandCapability, EncryptPolicy, RecipientTrustOutcome,
    TrustContext, WorkspaceMemberSnapshot, WriteRecipientTrustPlan,
};
use crate::feature::context::crypto::build_signing_context;
use crate::feature::encrypt::encrypt_file_content;
use crate::format::content::{EncContent, FileEncContent};
use crate::io::workspace::detection::WorkspaceRoot;
use crate::Result;

/// What an encrypt says when the member set it was authorized against moved.
const ENCRYPT_MEMBERS_CHANGED_MESSAGE: &str =
    "Encrypt active members changed since review and must be reviewed again.";

/// What an encrypt says when the trust store it was authorized against moved.
const ENCRYPT_TRUST_STORE_CHANGED_MESSAGE: &str =
    "Encrypt trust store changed since review and must be reviewed again.";

pub struct EncryptFileCommand<'a> {
    pub execution: &'a ExecutionContext,
    pub warnings: Vec<String>,
    input_bytes: Vec<u8>,
    members: WorkspaceMemberSnapshot,
    trust_store: ReviewedTrustStore<'a>,
    pub recipient_trust: RecipientTrustOutcome,
    trust_context: TrustContext,
}

impl EncryptFileCommand<'_> {
    /// Confirm the authorization this command was granted still holds.
    ///
    /// The operator decided against one member set and one trust store, and both
    /// are read again from the trees this command fixed rather than from the
    /// paths naming them. What the encryption writes is a new file, so there is
    /// no reviewed target to compare: the member set and the trust store are the
    /// whole of what the decision rested on.
    pub fn ensure_current_after_confirmation(&self) -> Result<()> {
        ensure_workspace_members_match_snapshot(
            self.execution.fixed_workspace_directory()?,
            &self.members,
            ENCRYPT_MEMBERS_CHANGED_MESSAGE,
        )?;
        self.trust_store.ensure_current()
    }
}

/// Resolve one file encryption against the identity the command already fixed.
pub fn resolve_encrypt_file_command<'a>(
    options: &CommonCommandOptions,
    execution: &'a ExecutionContext,
    input_bytes: Vec<u8>,
) -> Result<EncryptFileCommand<'a>> {
    execution
        .key_ctx
        .inner()
        .enforce_signing_key_not_expired()?;
    // Encrypt names its own missing-workspace failure. The member set itself is
    // read through the workspace descriptor the execution fixed.
    require_encrypt_workspace(execution)?;
    let keystore = execution.require_local_keystore_access("Encrypt")?;
    let trust_plan = WriteRecipientTrustPlan::<EncryptPolicy>::load(
        options,
        execution,
        Some(execution.key_ctx.inner().local_key_identity()),
        keystore,
    )?;
    let trust_store = ReviewedTrustStore::load(
        execution,
        trust_plan.trust_context(),
        ENCRYPT_TRUST_STORE_CHANGED_MESSAGE,
    )?;
    let mut warnings = build_write_execution_warnings(execution)?;
    warnings.extend(trust_plan.warnings().iter().cloned());

    Ok(EncryptFileCommand {
        execution,
        warnings,
        input_bytes,
        members: trust_plan.workspace_members().clone(),
        trust_store,
        recipient_trust: trust_plan.recipient_trust().clone(),
        trust_context: trust_plan.trust_context().clone(),
    })
}

pub fn execute_encrypt_file_command(command: &EncryptFileCommand) -> Result<String> {
    let signing = build_signing_context(command.execution.key_ctx.inner())?;
    encrypt_file_content(
        &command.input_bytes,
        command.members.member_handles(),
        command.members.verified_recipients(),
        &signing,
    )
}

pub fn execute_encrypt_file_command_with_recipient_set_confirmation<ConfirmRecipientSet>(
    options: &CommonCommandOptions,
    command: &EncryptFileCommand,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<String>
where
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let encrypted = execute_encrypt_file_command(command)?;
    let content = EncContent::FileEnc(FileEncContent::new_unchecked(encrypted.clone()));
    review_artifact_output_recipient_set(
        ArtifactOutputRecipientSetReviewInput {
            options,
            execution: command.execution,
            trust_ctx: &command.trust_context,
            content: &content,
            capability: CommandCapability::Encrypt,
            context_label: "encrypt output member set",
        },
        confirm_recipient_set,
    )?;
    Ok(encrypted)
}

fn require_encrypt_workspace(execution: &ExecutionContext) -> Result<WorkspaceRoot> {
    execution
        .workspace_root
        .clone()
        .ok_or_else(|| build_workspace_not_found_error("encrypt"))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_file_encrypt_test.rs"]
mod tests;
