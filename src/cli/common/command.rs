// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI command runners for trust-gated commands.
//! Resolves CLI inputs before handing fixed sessions to public services.

use crate::cli::common::context::CliContext;
use crate::cli::common::key_context::load_signing_key_context;
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::presentation::tty;
use crate::cli::common::trust::{
    confirm_non_member_acceptance, confirm_recipient_approvals, confirm_signer_key_approval,
    run_with_trust_command_session_reset_recovery,
};
use crate::cli::identity_prompt;
use crate::cli::options::ToCommonOptions;
use kapsaro_core::api::file::encrypt::EncryptFileCommand;
use kapsaro_core::api::key::build_missing_member_handle_error;
use kapsaro_core::api::kv::mutation::{
    reevaluate_mutation_write_plan_after_review, resolve_mutation_write_plan,
    MutationWriteTrustPlan,
};
use kapsaro_core::api::trust::review::{
    review_write_recipient_trust, SignerTrustLabels, TrustReviewContext,
    WriteRecipientTrustReviewPlan,
};
use kapsaro_core::api::trust::{
    RecipientTrustOutcome, SignerTrustOutcome, TrustCommandSession, WriteTrustOptions,
};
use kapsaro_core::api::workspace::WorkspaceWriteDirectories;
use kapsaro_core::{Error, Result};
use tracing::debug;

#[derive(Clone, Copy)]
pub(crate) struct ReadCommandLabels<'a> {
    pub context: &'a str,
    pub allow_non_member: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct WriteCommandLabels<'a> {
    pub signer_context: Option<(&'a str, &'a str)>,
    pub recipient_context: &'a str,
}

pub(crate) struct CliWriteSession {
    directories: WorkspaceWriteDirectories,
    trust: TrustCommandSession,
    options: WriteTrustOptions,
}

impl CliWriteSession {
    pub(crate) fn directories(&self) -> &WorkspaceWriteDirectories {
        &self.directories
    }

    pub(crate) fn trust(&self) -> &TrustCommandSession {
        &self.trust
    }

    pub(crate) fn options(&self) -> WriteTrustOptions {
        self.options
    }
}

pub(crate) trait WriteCommandPlan {
    fn trust_session(&self) -> &TrustCommandSession;
    fn warnings(&self) -> &[String];
    fn signer_trust(&self) -> Option<&SignerTrustOutcome>;
    fn recipient_trust(&self) -> &RecipientTrustOutcome;

    fn ensure_current_after_confirmation(&self) -> Result<()> {
        Ok(())
    }
}

pub(crate) fn resolve_cli_write_session(
    context: &CliContext,
    common: &impl ToCommonOptions,
    directories: WorkspaceWriteDirectories,
    member_handle: Option<String>,
    allow_expired_key: bool,
) -> Result<CliWriteSession> {
    let common = common.to_common_options();
    run_pre_signing_key_load_hook();
    let key_context = load_signing_key_context(context, &common, member_handle, None)?;
    let owner = key_context.member_handle().clone();
    let trust = TrustCommandSession::open(context.local_state()?, owner, key_context)?;
    let options = WriteTrustOptions::new(
        allow_expired_key,
        tty::is_interactive(),
        context.strict_key_checking(),
    );
    Ok(CliWriteSession {
        directories,
        trust,
        options,
    })
}

pub(crate) fn resolve_required_cli_member_handle(
    context: &CliContext,
    member_handle: Option<String>,
    allow_prompt: bool,
) -> Result<String> {
    require_member_handle_with_prompt(
        context.member_handle(member_handle)?,
        allow_prompt,
        identity_prompt::is_prompt_available(),
        identity_prompt::prompt_member_handle,
    )
}

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
        None => Err(build_cli_missing_member_handle_error(allow_prompt)),
    }
}

pub(crate) fn build_cli_missing_member_handle_error(include_prompt_hint: bool) -> Error {
    let prompt_hint = if include_prompt_hint {
        "\n3. Run in an interactive terminal for prompt"
    } else {
        ""
    };
    build_missing_member_handle_error(format!(
        "member handle not configured.\n\
         Reason: member handle is required but could not be determined.\n\
         Options:\n\
         1. Specify a member handle with --member-handle <handle>\n\
         2. Configure a default member handle explicitly{prompt_hint}"
    ))
}

pub(crate) fn run_write_command_with_trust<Plan, T, Execute>(
    plan: &Plan,
    labels: WriteCommandLabels<'_>,
    execute: Execute,
) -> Result<T>
where
    Plan: WriteCommandPlan,
    Execute: FnOnce() -> Result<T>,
{
    review_write_command_trust(plan, labels)?;
    execute()
}

fn review_write_command_trust<Plan>(plan: &Plan, labels: WriteCommandLabels<'_>) -> Result<()>
where
    Plan: WriteCommandPlan,
{
    log_write_command_trust_gate(plan);
    review_write_recipient_trust(
        TrustReviewContext {
            trust: plan.trust_session(),
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

pub(crate) fn run_kv_write_command_with_recovery<T, Execute>(
    session: &CliWriteSession,
    file_name: Option<&str>,
    allow_missing: bool,
    labels: WriteCommandLabels<'_>,
    mut execute: Execute,
) -> Result<T>
where
    Execute: FnMut(&MutationWriteTrustPlan<'_>) -> Result<T>,
{
    run_with_trust_command_session_reset_recovery(session.trust(), || {
        let trust_plan = resolve_mutation_write_plan(
            session.directories(),
            session.trust(),
            session.options(),
            file_name,
            allow_missing,
        )?;
        review_write_command_trust(&trust_plan, labels)?;
        let trust_plan = reevaluate_mutation_write_plan_after_review(trust_plan)?;
        execute(&trust_plan)
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

impl WriteCommandPlan for EncryptFileCommand<'_> {
    fn trust_session(&self) -> &TrustCommandSession {
        self.trust_session()
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

impl WriteCommandPlan for MutationWriteTrustPlan<'_> {
    fn trust_session(&self) -> &TrustCommandSession {
        self.trust_session()
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

// Test-only seam: fires once after workspace directories have been opened and
// before signing-key or SSH access begins. This lets a test replace the path
// and prove the session continues through the descriptors it already holds.
#[cfg(test)]
thread_local! {
    static PRE_SIGNING_KEY_LOAD_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_pre_signing_key_load_hook(hook: impl FnOnce() + 'static) {
    PRE_SIGNING_KEY_LOAD_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
}

#[cfg(test)]
fn run_pre_signing_key_load_hook() {
    if let Some(hook) = PRE_SIGNING_KEY_LOAD_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(not(test))]
fn run_pre_signing_key_load_hook() {}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_command_test.rs"]
mod cli_common_command_test;
