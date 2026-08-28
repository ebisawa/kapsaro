// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Registration command entry point.
//! Drives workspace creation, key generation and member registration.

mod output;

use crate::cli::common::command::{require_member_handle, resolve_options};
use crate::cli::common::output::text::registration::print_init_noop_summary;
use crate::cli::common::ssh::resolve_ssh_context;
use crate::cli::identity_prompt;
use crate::cli::options::ToCommonOptions;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::registration::command::{
    evaluate_registration_decision, execute_registration_decision, resolve_registration_command,
    RegistrationDecision,
};
use kapsaro_core::cli_api::app::registration::key_plan::open_registration_local_state;
use kapsaro_core::cli_api::app::registration::types::{RegistrationCommand, RegistrationMode};
use kapsaro_core::cli_api::app::registration::{
    ensure_init_workspace_structure, evaluate_init_workspace_status, InitWorkspaceState,
};
use kapsaro_core::Error;
use output::{print_missing_key_notice, print_registration_outcome};

pub(crate) fn run_registration_command(
    common: impl ToCommonOptions,
    force: bool,
    github_user: Option<String>,
    member_handle: Option<String>,
    mode: RegistrationMode,
) -> Result<(), Error> {
    let options = resolve_options(&common);
    if handle_init_noop(&options, mode)? {
        return Ok(());
    }

    let command =
        resolve_registration_command_from_local_state(&options, member_handle, github_user, mode)?;
    let outcome =
        execute_registration_decision(&command, resolve_registration_decision(&command, force)?)?;
    print_registration_outcome(&outcome)?;
    Ok(())
}

/// Handle the `init` mode's no-op case, where the workspace already exists.
/// Returns whether the command was fully handled here.
fn handle_init_noop(options: &CommonCommandOptions, mode: RegistrationMode) -> Result<bool, Error> {
    if let RegistrationMode::Init = mode {
        let init_workspace = evaluate_init_workspace_status(options)?;
        if init_workspace.state == InitWorkspaceState::NoOp {
            ensure_init_workspace_structure(&init_workspace.workspace_path)?;
            print_init_noop_summary(&init_workspace.workspace_path);
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolve the member handle, key plan, GitHub user and SSH context from local
/// state, then build the `RegistrationCommand` they decide together.
fn resolve_registration_command_from_local_state(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    github_user: Option<String>,
    mode: RegistrationMode,
) -> Result<RegistrationCommand, Error> {
    // One opened local state directory answers both the member handle fallback
    // and the key plan, so a generated key lands where the plan was decided.
    let local_state = open_registration_local_state(options)?;
    let member_handle = require_member_handle(
        local_state.resolve_optional_member_handle(member_handle)?,
        true,
    )?;
    let key_plan = local_state.resolve_key_plan(&member_handle)?;
    let needs_new_key = key_plan.needs_new_key();
    if needs_new_key {
        print_missing_key_notice(&member_handle);
    }
    let github_user = resolve_registration_github_user(needs_new_key, github_user, options)?;
    let ssh_ctx = resolve_registration_ssh_context(needs_new_key, options)?;
    resolve_registration_command(options, member_handle, github_user, key_plan, mode, ssh_ctx)
}

fn resolve_registration_decision(
    command: &RegistrationCommand,
    force: bool,
) -> Result<RegistrationDecision, Error> {
    let decision =
        evaluate_registration_decision(command, force, identity_prompt::is_prompt_available())?;
    match decision {
        RegistrationDecision::ConfirmOverwrite => {
            if identity_prompt::confirm_member_overwrite(&command.setup.member_handle)? {
                Ok(RegistrationDecision::Apply { overwrite: true })
            } else {
                Ok(RegistrationDecision::Return(
                    kapsaro_core::cli_api::app::registration::types::RegistrationResult::AlreadyExists,
                ))
            }
        }
        other => Ok(other),
    }
}

fn resolve_registration_github_user(
    needs_new_key: bool,
    github_user: Option<String>,
    options: &CommonCommandOptions,
) -> Result<Option<String>, Error> {
    identity_prompt::resolve_key_generation_github_user(needs_new_key, github_user, options)
}

fn resolve_registration_ssh_context(
    needs_new_key: bool,
    options: &CommonCommandOptions,
) -> Result<Option<kapsaro_core::cli_api::app::context::ssh::SshSigningContextResolution>, Error> {
    if needs_new_key {
        Ok(Some(resolve_ssh_context(options)?))
    } else {
        Ok(None)
    }
}
