// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! run command v3 implementation
//!
//! Executes a command with decrypted environment variables.
//!
//! Features:
//! - Uses default kv-enc file (`<workspace>/secrets/default.kvenc`)
//! - Automatic verify --strict before decryption (MUST - cannot be skipped)
//! - Child process execution with decrypted environment
//! - Exit code forwarding

use clap::Args;
use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use crate::cli::common::command::{
    ensure_reviewed_artifact_unchanged, resolve_options_with_allow_expired_key,
    run_read_command_with_recovery, ReadCommandContext, ReadCommandLabels,
};
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningOptions,
};
use kapsaro_core::api::kv::{KvEncArtifact, KvReadOperation};
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::api::trust::TrustDecision;
use kapsaro_core::cli_api::app::context::execution::{
    resolve_read_execution, resolve_read_trust_evaluator,
};
use kapsaro_core::cli_api::app::kv::query::{evaluate_kv_read_trust_plan, resolve_kv_read_path};
use kapsaro_core::cli_api::app::trust::evaluate_kv_after_cli_review;
use kapsaro_core::cli_api::app::trust::RunPolicy;
use kapsaro_core::cli_api::presentation::process::remove_parent_kapsaro_env_vars;
use kapsaro_core::{Error, Result};
use tracing::debug;

#[derive(Args)]
pub(crate) struct RunArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// Command to execute (after --)
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

pub(crate) fn run(args: RunArgs) -> Result<i32> {
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let artifact_path = resolve_kv_read_path(&options, args.store.name.as_deref())?;
    let artifact = KvEncArtifact::load(&artifact_path)?;
    let verified = artifact.verify(options.operation_options())?;
    let exit_code = run_read_command_with_recovery(
        &options,
        args.member.member_handle.clone(),
        ReadCommandLabels {
            context: "run signer",
            subject: "run",
            workspace_purpose: "kv access",
            allow_non_member: false,
        },
        |ssh_ctx| {
            let execution =
                resolve_read_execution(&options, args.member.member_handle.clone(), None, ssh_ctx)?;
            let trust = evaluate_kv_read_trust_plan::<RunPolicy>(&options, &execution, &verified)?;
            Ok(ReadCommandContext::new(execution, trust))
        },
        |context| {
            let current_artifact = KvEncArtifact::load(&artifact_path)?;
            ensure_reviewed_artifact_unchanged(
                artifact.as_str(),
                current_artifact.as_str(),
                "KV run authorization",
            )?;
            let current = current_artifact.verify(options.operation_options())?;
            let evaluator = resolve_read_trust_evaluator(&options, &context.execution)?;
            debug!("[KV] env command: decrypt values");
            let env_vars = match evaluate_kv_after_cli_review(
                &evaluator,
                &verified,
                &current,
                &context.execution.key_ctx,
                KvReadOperation::Environment,
                context.signer_outcome(),
                options.operation_options(),
            )? {
                TrustDecision::Trusted(trusted) => trusted.decrypt_environment()?,
                TrustDecision::ReviewRequired(_) => {
                    return Err(Error::build_verification_error(
                        "E_TRUST_REVIEW_REQUIRED".to_string(),
                        "Trust state changed while reviewing the KV artifact".to_string(),
                    ));
                }
            };
            execute_child_command(&args.command, &env_vars)
        },
    )?;
    Ok(exit_code)
}

pub(crate) fn execute_child_command(
    command_args: &[String],
    env_vars: &BTreeMap<String, SecretString>,
) -> Result<i32> {
    let (program, args) = command_args
        .split_first()
        .ok_or_else(|| Error::build_config_error("No command specified".to_string()))?;
    debug!(
        "[CLI] child process: command={}, secret_environment_count={}",
        program,
        env_vars.len()
    );
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    configure_child_environment(&mut command, env_vars);
    let status = command.status().map_err(|error| {
        Error::build_io_error_with_source(
            format!("Failed to execute command '{}': {}", program, error),
            error,
        )
    })?;
    let code = status.code().unwrap_or(1);
    debug!(
        "[CLI] child process exited: command={}, code={}",
        program, code
    );
    Ok(code)
}

pub(crate) fn configure_child_environment(
    command: &mut Command,
    env_vars: &BTreeMap<String, SecretString>,
) {
    remove_parent_kapsaro_env_vars(command);
    for (key, value) in env_vars {
        command.env(key, value.expose_secret());
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_run_test.rs"]
mod tests;
