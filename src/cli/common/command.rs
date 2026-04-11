// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI command runners for trust-gated commands.

use crate::app::context::execution::{resolve_write_execution, ExecutionContext};
use crate::app::context::identity::{build_missing_member_id_error, resolve_member_id_input};
use crate::app::context::member::resolve_required_member;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::app::file::decrypt::DecryptFileCommand;
use crate::app::file::encrypt::EncryptFileCommand;
use crate::app::kv::mutation::{build_mutation_write_plan, MutationWriteTrustPlan};
use crate::app::kv::query::KvReadCommand;
use crate::app::trust::flow::{
    execute_read_with_signer_trust, execute_write_with_recipient_trust, ReadSignerTrustReviewPlan,
    SignerTrustLabels, TrustExecutionContext, WriteRecipientTrustReviewPlan,
};
use crate::app::trust::{RecipientTrustOutcome, SignerTrustOutcome, WriteTrustPolicy};
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::cli::common::trust::{
    confirm_known_key_approval, confirm_non_member_acceptance, confirm_recipient_approvals,
};
use crate::cli::identity_prompt;
use crate::cli::options::CommonOptions;
use crate::feature::context::env_key::is_env_key_mode;
use crate::Result;

pub(crate) struct ReadCommandLabels<'a> {
    pub context: &'a str,
    pub subject: &'a str,
    pub allow_non_member: bool,
}

pub(crate) struct WriteCommandLabels<'a> {
    pub signer_context: Option<(&'a str, &'a str)>,
    pub recipient_context: &'a str,
}

pub(crate) trait ReadCommandPlan {
    fn execution(&self) -> &ExecutionContext;
    fn warnings(&self) -> &[String];
    fn signer_trust(&self) -> &SignerTrustOutcome;
}

pub(crate) trait WriteCommandPlan {
    fn execution(&self) -> &ExecutionContext;
    fn warnings(&self) -> &[String];
    fn signer_trust(&self) -> Option<&SignerTrustOutcome>;
    fn recipient_trust(&self) -> &RecipientTrustOutcome;
}

pub(crate) fn resolve_command_input(
    common: &CommonOptions,
    member_id: Option<String>,
) -> Result<(CommonCommandOptions, Option<ResolvedSshSigner>)> {
    let options = resolve_options(common);
    let ssh_ctx = resolve_ssh_context_optional(&options, member_id)?;
    Ok((options, ssh_ctx))
}

pub(crate) fn resolve_options(common: &CommonOptions) -> CommonCommandOptions {
    CommonCommandOptions::from(common)
}

pub(crate) fn resolve_required_member_id(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    allow_prompt: bool,
) -> Result<String> {
    resolve_required_member_id_with_prompt(
        options,
        member_id,
        allow_prompt,
        identity_prompt::is_prompt_available(),
        identity_prompt::prompt_member_id,
    )
}

pub(crate) fn resolve_required_member_id_with_prompt<F>(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    allow_prompt: bool,
    prompt_available: bool,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match resolve_member_id_input(member_id, options.home.as_deref())? {
        Some(member_id) => Ok(member_id),
        None if allow_prompt && prompt_available => prompt(),
        None => Err(build_missing_member_id_error(allow_prompt)),
    }
}

pub(crate) fn resolve_execution_input(
    common: &CommonOptions,
    member_id: Option<String>,
) -> Result<(CommonCommandOptions, ExecutionContext)> {
    let (options, ssh_ctx) = resolve_command_input(common, member_id.clone())?;
    let execution = resolve_write_execution(&options, member_id, ssh_ctx)?;
    Ok((options, execution))
}

pub(crate) fn resolve_trust_store_owner_member(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<String> {
    match resolve_required_member(options, member_id.clone()) {
        Ok(member_id) => Ok(member_id),
        Err(_) if is_env_key_mode() => Ok(resolve_write_execution(options, member_id, None)?
            .member_id
            .to_string()),
        Err(error) => Err(error),
    }
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
    execute_read_with_signer_trust(
        TrustExecutionContext {
            options,
            execution: plan.execution(),
            warnings: plan.warnings(),
        },
        ReadSignerTrustReviewPlan {
            trust_outcome: plan.signer_trust(),
            labels: SignerTrustLabels {
                context: labels.context,
                subject: labels.subject,
            },
            allow_non_member: labels.allow_non_member,
        },
        print_warnings,
        confirm_known_key_approval,
        confirm_non_member_acceptance,
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
    execute_write_with_recipient_trust(
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
        confirm_known_key_approval,
        confirm_non_member_acceptance,
        confirm_recipient_approvals,
        execute,
    )
}

pub(crate) fn run_kv_write_command_with_trust<P, T, Execute>(
    common: &CommonOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    allow_missing: bool,
    labels: WriteCommandLabels<'_>,
    execute: Execute,
) -> Result<T>
where
    P: WriteTrustPolicy,
    Execute: FnOnce(&CommonCommandOptions, &MutationWriteTrustPlan<P>) -> Result<T>,
{
    let (options, ssh_ctx) = resolve_command_input(common, member_id.clone())?;
    let trust_plan =
        build_mutation_write_plan::<P>(&options, member_id, file_name, allow_missing, ssh_ctx)?;
    run_write_command_with_trust(&options, &trust_plan, labels, || {
        execute(&options, &trust_plan)
    })
}

impl ReadCommandPlan for DecryptFileCommand {
    fn execution(&self) -> &ExecutionContext {
        &self.execution
    }

    fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn signer_trust(&self) -> &SignerTrustOutcome {
        &self.trust_outcome
    }
}

impl ReadCommandPlan for KvReadCommand {
    fn execution(&self) -> &ExecutionContext {
        &self.execution
    }

    fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn signer_trust(&self) -> &SignerTrustOutcome {
        &self.trust_outcome
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
}

#[cfg(test)]
#[path = "../../../tests/unit/cli_common_command_test.rs"]
mod tests;
