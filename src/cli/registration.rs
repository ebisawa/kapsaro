// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

mod output;

use crate::app::registration::command::{
    evaluate_registration_decision, execute_registration_decision, resolve_registration_command,
    RegistrationDecision,
};
use crate::app::registration::key_plan::resolve_registration_key_plan;
use crate::app::registration::types::{RegistrationCommand, RegistrationMode};
use crate::app::registration::{
    ensure_init_workspace_structure, evaluate_init_workspace_status, InitWorkspaceState,
};
use crate::cli::common::command::{resolve_options, resolve_required_member_handle};
use crate::cli::common::ssh::resolve_ssh_context;
use crate::cli::identity_prompt;
use crate::cli::options::ToCommonOptions;
use crate::Error;
use output::{print_init_noop_message, print_missing_key_notice, print_registration_outcome};

pub(crate) fn run_registration_command(
    common: impl ToCommonOptions,
    force: bool,
    github_user: Option<String>,
    member_handle: Option<String>,
    mode: RegistrationMode,
) -> Result<(), Error> {
    let options = resolve_options(&common);
    if let RegistrationMode::Init = mode {
        let init_workspace = evaluate_init_workspace_status(&options)?;
        if init_workspace.state == InitWorkspaceState::NoOp {
            ensure_init_workspace_structure(&init_workspace.workspace_path)?;
            print_init_noop_message(&init_workspace.workspace_path);
            return Ok(());
        }
    }

    let keystore_root = options.resolve_keystore_root()?;
    let member_handle = resolve_required_member_handle(&options, member_handle, true)?;
    let key_plan = resolve_registration_key_plan(&member_handle, &keystore_root)?;
    let needs_new_key = key_plan.needs_new_key();
    if needs_new_key {
        print_missing_key_notice(&member_handle);
    }
    let github_user = resolve_registration_github_user(needs_new_key, github_user, &options)?;

    let ssh_ctx = resolve_registration_ssh_context(needs_new_key, &options)?;
    let command = match mode {
        RegistrationMode::Init | RegistrationMode::Join => resolve_registration_command(
            &options,
            member_handle,
            github_user,
            key_plan,
            mode,
            ssh_ctx,
        )?,
    };
    let outcome =
        execute_registration_decision(&command, resolve_registration_decision(&command, force)?)?;
    print_registration_outcome(&outcome)?;
    Ok(())
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
                    crate::app::registration::types::RegistrationResult::AlreadyExists,
                ))
            }
        }
        other => Ok(other),
    }
}

fn resolve_registration_github_user(
    needs_new_key: bool,
    github_user: Option<String>,
    options: &crate::app::context::options::CommonCommandOptions,
) -> Result<Option<String>, Error> {
    identity_prompt::resolve_key_generation_github_user(
        needs_new_key,
        github_user,
        options.home.as_deref(),
    )
}

fn resolve_registration_ssh_context(
    needs_new_key: bool,
    options: &crate::app::context::options::CommonCommandOptions,
) -> Result<Option<crate::app::context::ssh::SshSigningContextResolution>, Error> {
    if needs_new_key {
        Ok(Some(resolve_ssh_context(options)?))
    } else {
        Ok(None)
    }
}
