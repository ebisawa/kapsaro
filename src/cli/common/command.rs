// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI command runners for trust-gated commands.

use crate::cli::common::output::text::print_warnings;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::cli::common::trust::{
    confirm_non_member_acceptance, confirm_recipient_approvals, confirm_signer_key_approval,
    run_with_trust_store_reset_recovery,
};
use crate::cli::identity_prompt;
use crate::cli::options::ToCommonOptions;
use kapsaro_core::cli_api::app::context::env_key::is_env_key_mode;
use kapsaro_core::cli_api::app::context::execution::{resolve_write_execution, ExecutionContext};
use kapsaro_core::cli_api::app::context::identity::{
    build_missing_member_handle_error, resolve_member_handle_input,
};
use kapsaro_core::cli_api::app::context::member::resolve_required_member;
use kapsaro_core::cli_api::app::context::options::{
    resolve_allow_expired_key_option, resolve_allow_non_member_option, CommonCommandOptions,
};
use kapsaro_core::cli_api::app::context::paths::require_workspace;
use kapsaro_core::cli_api::app::context::ssh::SshSigningContextResolution;
use kapsaro_core::cli_api::app::file::encrypt::EncryptFileCommand;
use kapsaro_core::cli_api::app::kv::mutation::{
    reevaluate_mutation_write_plan_after_review, resolve_mutation_write_plan,
    MutationWriteTrustPlan,
};
use kapsaro_core::cli_api::app::trust::review::{
    execute_read_with_signer_trust, review_write_recipient_trust, ReadSignerTrustReviewPlan,
    SignerTrustLabels, TrustExecutionContext, WriteRecipientTrustReviewPlan,
};
use kapsaro_core::cli_api::app::trust::{
    ReadArtifactTrustPlan, RecipientTrustOutcome, SignerTrustOutcome, WriteTrustPolicy,
};
use kapsaro_core::{Error, Result};
use tracing::debug;

#[derive(Clone, Copy)]
pub(crate) struct ReadCommandLabels<'a> {
    pub context: &'a str,
    pub subject: &'a str,
    pub workspace_purpose: &'a str,
    pub allow_non_member: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct WriteCommandLabels<'a> {
    pub signer_context: Option<(&'a str, &'a str)>,
    pub recipient_context: &'a str,
}

pub(crate) trait ReadCommandPlan {
    fn execution(&self) -> &ExecutionContext;
    fn warnings(&self) -> &[String];
    fn signer_trust(&self) -> &SignerTrustOutcome;
    fn recipient_trust(&self) -> &RecipientTrustOutcome;
}

pub(crate) trait WriteCommandPlan {
    fn execution(&self) -> &ExecutionContext;
    fn warnings(&self) -> &[String];
    fn signer_trust(&self) -> Option<&SignerTrustOutcome>;
    fn recipient_trust(&self) -> &RecipientTrustOutcome;

    fn ensure_current_after_confirmation(&self) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct ReadCommandContext {
    pub(crate) execution: ExecutionContext,
    trust: ReadArtifactTrustPlan,
}

impl ReadCommandContext {
    pub(crate) fn new(execution: ExecutionContext, trust: ReadArtifactTrustPlan) -> Self {
        Self { execution, trust }
    }

    pub(crate) fn signer_outcome(&self) -> &SignerTrustOutcome {
        &self.trust.signer_outcome
    }
}

pub(crate) fn ensure_reviewed_artifact_unchanged(
    reviewed: &str,
    current: &str,
    operation: &str,
) -> Result<()> {
    if reviewed == current {
        return Ok(());
    }
    Err(Error::build_verification_error(
        "E_TRUST_TARGET_CHANGED".to_string(),
        format!("Reviewed artifact changed before {operation}; run the command again"),
    ))
}

pub(crate) fn resolve_options(common: &impl ToCommonOptions) -> CommonCommandOptions {
    CommonCommandOptions::from(&common.to_common_options())
}

pub(crate) fn resolve_options_with_allow_expired_key(
    common: &impl ToCommonOptions,
    allow_expired_key: bool,
) -> Result<CommonCommandOptions> {
    let mut options = resolve_options(common);
    options.allow_expired_key =
        resolve_allow_expired_key_option(Some(allow_expired_key), &options)?;
    Ok(options)
}

pub(crate) fn resolve_options_with_read_trust_allowances(
    common: &impl ToCommonOptions,
    allow_expired_key: bool,
    allow_non_member: bool,
) -> Result<CommonCommandOptions> {
    let mut options = resolve_options(common);
    options.allow_expired_key =
        resolve_allow_expired_key_option(Some(allow_expired_key), &options)?;
    options.allow_non_member = resolve_allow_non_member_option(Some(allow_non_member), &options)?;
    Ok(options)
}

pub(crate) fn resolve_required_member_handle(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    allow_prompt: bool,
) -> Result<String> {
    resolve_required_member_handle_with_prompt(
        options,
        member_handle,
        allow_prompt,
        identity_prompt::is_prompt_available(),
        identity_prompt::prompt_member_handle,
    )
}

pub(crate) fn resolve_required_member_handle_with_prompt<F>(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    allow_prompt: bool,
    prompt_available: bool,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match resolve_member_handle_input(member_handle, options.home.as_deref())? {
        Some(member_handle) => Ok(member_handle),
        None if allow_prompt && prompt_available => prompt(),
        None => Err(build_missing_member_handle_error(allow_prompt)),
    }
}

pub(crate) fn resolve_write_execution_input(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<ExecutionContext> {
    let ssh_ctx = resolve_ssh_context_optional(options, member_handle.clone())?;
    resolve_write_execution(options, member_handle, ssh_ctx)
}

pub(crate) fn resolve_trust_store_owner_member(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<String> {
    match resolve_required_member(options, member_handle.clone()) {
        Ok(member_handle) => Ok(member_handle),
        Err(_) if is_env_key_mode() => Ok(resolve_write_execution(options, member_handle, None)?
            .member_handle
            .to_string()),
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_workspace_required(
    options: &CommonCommandOptions,
    purpose: &str,
) -> Result<()> {
    require_workspace(options, purpose).map(|_| ())
}

pub(crate) fn run_read_command_with_trust<Plan, T, Execute>(
    options: &CommonCommandOptions,
    plan: &Plan,
    labels: ReadCommandLabels<'_>,
    execute: Execute,
) -> Result<T>
where
    Plan: ReadCommandPlan,
    Execute: FnOnce() -> Result<T>,
{
    debug!(
        "[TRUST] read gate: signer={}, recipients={}, allow_non_member={}",
        describe_signer_trust(plan.signer_trust()),
        describe_recipient_trust(plan.recipient_trust()),
        labels.allow_non_member
    );
    execute_read_with_signer_trust(
        TrustExecutionContext {
            options,
            execution: plan.execution(),
            warnings: plan.warnings(),
        },
        ReadSignerTrustReviewPlan {
            trust_outcome: plan.signer_trust(),
            recipient_trust_outcome: plan.recipient_trust(),
            labels: SignerTrustLabels {
                context: labels.context,
                subject: labels.subject,
            },
            allow_non_member: labels.allow_non_member,
        },
        print_warnings,
        confirm_signer_key_approval,
        confirm_non_member_acceptance,
        confirm_recipient_approvals,
        execute,
    )
}

pub(crate) fn run_write_command_with_trust<Plan, T, Execute>(
    options: &CommonCommandOptions,
    plan: &Plan,
    labels: WriteCommandLabels<'_>,
    execute: Execute,
) -> Result<T>
where
    Plan: WriteCommandPlan,
    Execute: FnOnce() -> Result<T>,
{
    review_write_command_trust(options, plan, labels)?;
    execute()
}

fn review_write_command_trust<Plan>(
    options: &CommonCommandOptions,
    plan: &Plan,
    labels: WriteCommandLabels<'_>,
) -> Result<()>
where
    Plan: WriteCommandPlan,
{
    debug!(
        "[TRUST] write gate: signer={}, recipients={}",
        plan.signer_trust()
            .map(describe_signer_trust)
            .unwrap_or("not-applicable"),
        describe_recipient_trust(plan.recipient_trust())
    );
    review_write_recipient_trust(
        TrustExecutionContext {
            options,
            execution: plan.execution(),
            warnings: plan.warnings(),
        },
        WriteRecipientTrustReviewPlan {
            signer_trust: labels.signer_context.and_then(|(context, subject)| {
                plan.signer_trust()
                    .map(|trust_outcome| (trust_outcome, SignerTrustLabels { context, subject }))
            }),
            recipient_trust: plan.recipient_trust(),
            recipient_context_label: labels.recipient_context,
        },
        print_warnings,
        |candidate, context| {
            let confirmed = confirm_signer_key_approval(candidate, context)?;
            plan.ensure_current_after_confirmation()?;
            Ok(confirmed)
        },
        |candidate, subject, recipients| {
            let confirmed = confirm_non_member_acceptance(candidate, subject, recipients)?;
            plan.ensure_current_after_confirmation()?;
            Ok(confirmed)
        },
        |candidates, context| {
            let approved = confirm_recipient_approvals(candidates, context)?;
            plan.ensure_current_after_confirmation()?;
            Ok(approved)
        },
    )
}

pub(crate) fn run_kv_write_command_with_trust<P, T, Execute>(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    file_name: Option<&str>,
    allow_missing: bool,
    labels: WriteCommandLabels<'_>,
    execute: Execute,
) -> Result<T>
where
    P: WriteTrustPolicy,
    Execute: FnOnce(&CommonCommandOptions, &MutationWriteTrustPlan<P>) -> Result<T>,
{
    let ssh_ctx = resolve_ssh_context_optional(options, member_handle.clone())?;
    let trust_plan = resolve_mutation_write_plan::<P>(
        options,
        member_handle,
        file_name,
        allow_missing,
        ssh_ctx,
    )?;
    review_write_command_trust(options, &trust_plan, labels)?;
    let trust_plan = reevaluate_mutation_write_plan_after_review(trust_plan)?;
    execute(options, &trust_plan)
}

pub(crate) fn run_read_command_with_recovery<Plan, T, ResolvePlan, Execute>(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    labels: ReadCommandLabels<'_>,
    mut resolve_plan: ResolvePlan,
    mut execute: Execute,
) -> Result<T>
where
    Plan: ReadCommandPlan,
    ResolvePlan: FnMut(Option<SshSigningContextResolution>) -> Result<Plan>,
    Execute: FnMut(&Plan) -> Result<T>,
{
    ensure_workspace_required(options, labels.workspace_purpose)?;
    run_with_trust_store_reset_recovery(
        options,
        || resolve_trust_store_owner_member(options, member_handle.clone()),
        || {
            let ssh_ctx = resolve_ssh_context_optional(options, member_handle.clone())?;
            let command = resolve_plan(ssh_ctx)?;
            run_read_command_with_trust(options, &command, labels, || execute(&command))
        },
    )
}

pub(crate) fn run_kv_write_command_with_recovery<P, T, Execute>(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    file_name: Option<&str>,
    allow_missing: bool,
    labels: WriteCommandLabels<'_>,
    mut execute: Execute,
) -> Result<T>
where
    P: WriteTrustPolicy,
    Execute: FnMut(&CommonCommandOptions, &MutationWriteTrustPlan<P>) -> Result<T>,
{
    ensure_workspace_required(options, "kv mutation")?;
    run_with_trust_store_reset_recovery(
        options,
        || resolve_trust_store_owner_member(options, member_handle.clone()),
        || {
            run_kv_write_command_with_trust::<P, _, _>(
                options,
                member_handle.clone(),
                file_name,
                allow_missing,
                labels,
                |options, trust_plan| execute(options, trust_plan),
            )
        },
    )
}

fn describe_signer_trust(outcome: &SignerTrustOutcome) -> &'static str {
    match outcome {
        SignerTrustOutcome::Accepted => "accepted",
        SignerTrustOutcome::NeedsKnownKeyApproval(_) => "needs-known-key-approval",
        SignerTrustOutcome::NeedsNonMemberAcceptance { .. } => "needs-non-member-acceptance",
    }
}

fn describe_recipient_trust(outcome: &RecipientTrustOutcome) -> &'static str {
    match outcome {
        RecipientTrustOutcome::Accepted => "accepted",
        RecipientTrustOutcome::NeedsManualApproval(_) => "needs-manual-approval",
    }
}

impl ReadCommandPlan for ReadCommandContext {
    fn execution(&self) -> &ExecutionContext {
        &self.execution
    }

    fn warnings(&self) -> &[String] {
        &self.trust.warnings
    }

    fn signer_trust(&self) -> &SignerTrustOutcome {
        &self.trust.signer_outcome
    }

    fn recipient_trust(&self) -> &RecipientTrustOutcome {
        &self.trust.recipient_outcome
    }
}

impl WriteCommandPlan for EncryptFileCommand {
    fn execution(&self) -> &ExecutionContext {
        &self.execution
    }

    fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn signer_trust(&self) -> Option<&SignerTrustOutcome> {
        None
    }

    fn recipient_trust(&self) -> &RecipientTrustOutcome {
        &self.recipient_trust
    }
}

impl<P> WriteCommandPlan for MutationWriteTrustPlan<P> {
    fn execution(&self) -> &ExecutionContext {
        &self.execution
    }

    fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn signer_trust(&self) -> Option<&SignerTrustOutcome> {
        self.signer_trust.as_ref()
    }

    fn recipient_trust(&self) -> &RecipientTrustOutcome {
        &self.recipient_trust
    }

    fn ensure_current_after_confirmation(&self) -> Result<()> {
        MutationWriteTrustPlan::ensure_current_after_confirmation(self)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_command_test.rs"]
mod tests;
