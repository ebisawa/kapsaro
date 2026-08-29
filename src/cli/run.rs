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

use crate::cli::common::command::{resolve_options_with_allow_expired_key, ReadCommandLabels};
use crate::cli::common::kv_read::KvReadSession;
use crate::cli::common::output::text::print_local_state_diagnostics;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningOptions,
};
use kapsaro_core::api::diagnostics::take_local_state_warnings;
use kapsaro_core::api::kv::KvReadOperation;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::cli_api::app::kv::query::evaluate_kv_read_trust_plan;
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
    let session = KvReadSession::open(
        options,
        args.store.name.as_deref(),
        args.member.member_handle.clone(),
    )?;
    session.read(
        ReadCommandLabels {
            context: "run signer",
            subject: "run",
            allow_non_member: false,
        },
        "KV run authorization",
        evaluate_kv_read_trust_plan::<RunPolicy>,
        |review| {
            debug!("[KV] env command: decrypt values");
            let env_vars = review
                .authorize(KvReadOperation::Environment)?
                .decrypt_environment()?;
            execute_child_command(&args.command, &env_vars)
        },
    )
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
    // Drain and show local state warnings before blocking on the child: `status()`
    // does not return until the child exits, and an unhandled Ctrl-C would drop
    // the warnings recorded during key loading before the deferred drain in cli.rs runs.
    print_local_state_diagnostics(&take_local_state_warnings());
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
