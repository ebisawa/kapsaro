// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

mod output;

use crate::app::registration::command::{
    build_registration, build_registration_decision, finalize_registration, RegistrationDecision,
};
use crate::app::registration::key_plan::resolve_registration_key_plan;
use crate::app::registration::types::{RegistrationCommand, RegistrationMode};
use crate::cli::common::command::{resolve_options, resolve_required_member_id};
use crate::cli::common::ssh::resolve_ssh_context;
use crate::cli::identity_prompt;
use crate::cli::options::CommonOptions;
use crate::Error;
use output::{print_missing_key_notice, print_registration_outcome};

pub(crate) fn execute_registration_command(
    common: CommonOptions,
    force: bool,
    github_user: Option<String>,
    member_id: Option<String>,
    mode: RegistrationMode,
) -> Result<(), Error> {
    let options = resolve_options(&common);
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = resolve_required_member_id(&options, member_id, true)?;
    let key_plan = resolve_registration_key_plan(&member_id, &keystore_root)?;
    let needs_new_key = key_plan.needs_new_key();
    if needs_new_key {
        print_missing_key_notice(&member_id);
    }
    let github_user = resolve_registration_github_user(needs_new_key, github_user, &options)?;

    eprintln!();
    let ssh_ctx = resolve_registration_ssh_context(needs_new_key, &options)?;
    let command = match mode {
        RegistrationMode::Init | RegistrationMode::Join => {
            build_registration(&options, member_id, github_user, key_plan, mode, ssh_ctx)?
        }
    };
    let outcome = finalize_registration(&command, resolve_registration_decision(&command, force)?)?;
    print_registration_outcome(&outcome)?;
    Ok(())
}

fn resolve_registration_decision(
    command: &RegistrationCommand,
    force: bool,
) -> Result<RegistrationDecision, Error> {
    let decision =
        build_registration_decision(command, force, identity_prompt::is_prompt_available())?;
    match decision {
        RegistrationDecision::ConfirmOverwrite => {
            if identity_prompt::confirm_member_overwrite(&command.setup.member_id)? {
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
) -> Result<Option<crate::app::context::ssh::ResolvedSshSigningContext>, Error> {
    if needs_new_key {
        Ok(Some(resolve_ssh_context(options)?))
    } else {
        Ok(None)
    }
}
