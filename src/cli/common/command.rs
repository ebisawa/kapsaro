// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI command runners for trust-gated commands.

use crate::cli::common::output::text::print_warnings;
use crate::cli::common::trust::{
    confirm_non_member_acceptance, confirm_recipient_approvals, confirm_signer_key_approval,
    run_with_execution_trust_store_reset_recovery,
};
use crate::cli::identity_prompt;
use crate::cli::options::ToCommonOptions;
use kapsaro_core::cli_api::app::context::execution::{
    resolve_read_execution, resolve_write_execution, ExecutionContext,
};
use kapsaro_core::cli_api::app::context::identity::{
    build_missing_member_handle_error, resolve_member_handle_input,
};
use kapsaro_core::cli_api::app::context::options::{
    resolve_allow_expired_key_option, resolve_read_trust_allowances, CommonCommandOptions,
};
use kapsaro_core::cli_api::app::context::paths::require_workspace;
use kapsaro_core::cli_api::app::file::encrypt::EncryptFileCommand;
use kapsaro_core::cli_api::app::kv::mutation::{
    reevaluate_mutation_write_plan_after_review, resolve_mutation_write_plan,
    MutationWriteTrustPlan,
};
use kapsaro_core::cli_api::app::trust::review::{
    execute_read_with_signer_trust, review_write_recipient_trust, ReadSignerTrustReviewPlan,
    SignerTrustLabels, TrustExecutionContext, TrustReviewContext, WriteRecipientTrustReviewPlan,
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

pub(crate) struct ReadCommandContext<'a> {
    pub(crate) execution: &'a ExecutionContext,
    trust: ReadArtifactTrustPlan,
}

impl<'a> ReadCommandContext<'a> {
    pub(crate) fn new(execution: &'a ExecutionContext, trust: ReadArtifactTrustPlan) -> Self {
        Self { execution, trust }
    }

    pub(crate) fn signer_outcome(&self) -> &SignerTrustOutcome {
        &self.trust.signer_outcome
    }

    pub(crate) fn known_key_review(&self) -> kapsaro_core::api::trust::KnownKeyReview {
        self.trust.known_key_review
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
    let allowances =
        resolve_read_trust_allowances(Some(allow_expired_key), Some(allow_non_member), &options)?;
    options.allow_expired_key = allowances.allow_expired_key;
    options.allow_non_member = allowances.allow_non_member;
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

fn resolve_required_member_handle_with_prompt<F>(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    allow_prompt: bool,
    prompt_available: bool,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    require_member_handle_with_prompt(
        resolve_member_handle_input(member_handle, options)?,
        allow_prompt,
        prompt_available,
        prompt,
    )
}

/// Turn an already resolved member handle into a required one, prompting for
/// it when the command may ask and the terminal can answer.
pub(crate) fn require_member_handle(
    resolved: Option<String>,
    allow_prompt: bool,
) -> Result<String> {
    require_member_handle_with_prompt(
        resolved,
        allow_prompt,
        identity_prompt::is_prompt_available(),
        identity_prompt::prompt_member_handle,
    )
}

fn require_member_handle_with_prompt<F>(
    resolved: Option<String>,
    allow_prompt: bool,
    prompt_available: bool,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match resolved {
        Some(member_handle) => Ok(member_handle),
        None if allow_prompt && prompt_available => prompt(),
        None => Err(build_missing_member_handle_error(allow_prompt)),
    }
}

pub(crate) fn resolve_write_execution_input(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<ExecutionContext> {
    resolve_write_execution(options, member_handle)
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
        TrustReviewContext {
            trust: TrustExecutionContext {
                options,
                execution: plan.execution(),
            },
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
    log_write_command_trust_gate(plan);
    review_write_recipient_trust(
        TrustReviewContext {
            trust: TrustExecutionContext {
                options,
                execution: plan.execution(),
            },
            warnings: plan.warnings(),
        },
        build_write_recipient_trust_review_plan(plan, labels),
        print_warnings,
        |candidate, context| {
            confirm_then_ensure_current(plan, || confirm_signer_key_approval(candidate, context))
        },
        |candidate, subject, recipients| {
            confirm_then_ensure_current(plan, || {
                confirm_non_member_acceptance(candidate, subject, recipients)
            })
        },
        |candidates, context| {
            confirm_then_ensure_current(plan, || confirm_recipient_approvals(candidates, context))
        },
    )
}

/// Log the trust state a write command is about to review, before any prompt runs.
fn log_write_command_trust_gate<Plan>(plan: &Plan)
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
}

/// Assemble the recipient trust review plan the write gate confirms against.
fn build_write_recipient_trust_review_plan<'a, Plan>(
    plan: &'a Plan,
    labels: WriteCommandLabels<'a>,
) -> WriteRecipientTrustReviewPlan<'a>
where
    Plan: WriteCommandPlan,
{
    WriteRecipientTrustReviewPlan {
        signer_trust: labels.signer_context.and_then(|(context, subject)| {
            plan.signer_trust()
                .map(|trust_outcome| (trust_outcome, SignerTrustLabels { context, subject }))
        }),
        recipient_trust: plan.recipient_trust(),
        recipient_context_label: labels.recipient_context,
    }
}

/// Run one confirmation, then re-check the plan is still current.
///
/// Every write confirmation must be followed by this re-check before its
/// result is trusted, so the two steps are kept together here rather than
/// repeated at each call site.
fn confirm_then_ensure_current<Plan, T>(
    plan: &Plan,
    confirm: impl FnOnce() -> Result<T>,
) -> Result<T>
where
    Plan: WriteCommandPlan,
{
    let confirmed = confirm()?;
    plan.ensure_current_after_confirmation()?;
    Ok(confirmed)
}

pub(crate) fn run_kv_write_command_with_trust<P, T, Execute>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    file_name: Option<&str>,
    allow_missing: bool,
    labels: WriteCommandLabels<'_>,
    execute: Execute,
) -> Result<T>
where
    P: WriteTrustPolicy,
    Execute: FnOnce(&CommonCommandOptions, &MutationWriteTrustPlan<'_, P>) -> Result<T>,
{
    let trust_plan =
        resolve_mutation_write_plan::<P>(options, execution, file_name, allow_missing)?;
    review_write_command_trust(options, &trust_plan, labels)?;
    let trust_plan = reevaluate_mutation_write_plan_after_review(trust_plan)?;
    execute(options, &trust_plan)
}

/// Resolve the identity a read command acts as, before it reads trust state.
pub(crate) fn resolve_read_execution_input(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    explicit_kid: Option<&str>,
    workspace_purpose: &str,
) -> Result<ExecutionContext> {
    ensure_workspace_required(options, workspace_purpose)?;
    resolve_read_execution(options, member_handle, explicit_kid)
}

/// Run one read command under trust review, recovering an invalid trust store.
///
/// Planning and reset recovery both act through `execution`, so the store the
/// failing read used is the store the reset deletes.
pub(crate) fn run_read_command_with_recovery<'a, Plan, T, ResolvePlan, Execute>(
    options: &CommonCommandOptions,
    execution: &'a ExecutionContext,
    labels: ReadCommandLabels<'_>,
    mut resolve_plan: ResolvePlan,
    mut execute: Execute,
) -> Result<T>
where
    Plan: ReadCommandPlan,
    ResolvePlan: FnMut(&'a ExecutionContext) -> Result<Plan>,
    Execute: FnMut(&Plan) -> Result<T>,
{
    run_with_execution_trust_store_reset_recovery(execution, || {
        let command = resolve_plan(execution)?;
        run_read_command_with_trust(options, &command, labels, || execute(&command))
    })
}

/// Purpose reported when a KV mutation runs outside a workspace.
pub(crate) const KV_MUTATION_PURPOSE: &str = "kv mutation";

/// Resolve the identity a KV write acts as, before it reads trust state.
pub(crate) fn resolve_kv_write_execution_input(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<ExecutionContext> {
    ensure_workspace_required(options, KV_MUTATION_PURPOSE)?;
    resolve_write_execution_input(options, member_handle)
}

/// Run one KV write under trust review, recovering an invalid trust store.
///
/// Planning and reset recovery both act through `execution`, so the store the
/// failing write used is the store the reset deletes.
pub(crate) fn run_kv_write_command_with_recovery<P, T, Execute>(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    file_name: Option<&str>,
    allow_missing: bool,
    labels: WriteCommandLabels<'_>,
    mut execute: Execute,
) -> Result<T>
where
    P: WriteTrustPolicy,
    Execute: FnMut(&CommonCommandOptions, &MutationWriteTrustPlan<'_, P>) -> Result<T>,
{
    run_with_execution_trust_store_reset_recovery(execution, || {
        run_kv_write_command_with_trust::<P, _, _>(
            options,
            execution,
            file_name,
            allow_missing,
            labels,
            |options, trust_plan| execute(options, trust_plan),
        )
    })
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

impl ReadCommandPlan for ReadCommandContext<'_> {
    fn execution(&self) -> &ExecutionContext {
        self.execution
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

impl WriteCommandPlan for EncryptFileCommand<'_> {
    fn execution(&self) -> &ExecutionContext {
        self.execution
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

    fn ensure_current_after_confirmation(&self) -> Result<()> {
        EncryptFileCommand::ensure_current_after_confirmation(self)
    }
}

impl<P> WriteCommandPlan for MutationWriteTrustPlan<'_, P> {
    fn execution(&self) -> &ExecutionContext {
        self.execution
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
