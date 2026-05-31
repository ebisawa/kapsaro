// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::key::generate::{generate_and_save_key, AppKeyGenerationOptions};
use crate::app::key::github::{resolve_github_account, verify_preflight_github_binding};
use crate::app::key::timestamp::resolve_key_timestamps;
use crate::app::verification::OnlineVerificationStatus;
use crate::model::public_key::GithubAccount;
use crate::Result;

use super::types::{
    ActiveMembershipState, MemberKeySetupResult, MemberSetupResult, RegistrationCommand,
    RegistrationKeyPlan, RegistrationMode, RegistrationOutcome, RegistrationResult,
};
use super::workspace::{
    resolve_active_membership_state, resolve_registration_paths, save_registration_member,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationDecision {
    Apply { overwrite: bool },
    Return(RegistrationResult),
    ConfirmOverwrite,
}

pub fn resolve_registration_command(
    common: &CommonCommandOptions,
    member_handle: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    mode: RegistrationMode,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<RegistrationCommand> {
    let setup =
        ensure_registration_member_setup(common, member_handle, github_user, key_plan, ssh_ctx)?;
    resolve_registration_context(common, mode, setup)
}

pub fn execute_registration_command(
    command: &RegistrationCommand,
    overwrite: bool,
) -> Result<RegistrationOutcome> {
    let result = save_registration_member(
        &command.workspace_path,
        &command.setup.member_handle,
        command.setup.kid(),
        overwrite,
        &command.keystore_root,
        command.target,
    )?;

    Ok(build_registration_outcome(command, result))
}

pub fn execute_registration_decision(
    command: &RegistrationCommand,
    decision: RegistrationDecision,
) -> Result<RegistrationOutcome> {
    match decision {
        RegistrationDecision::Apply { overwrite } => {
            execute_registration_command(command, overwrite)
        }
        RegistrationDecision::Return(result) => Ok(build_registration_outcome(command, result)),
        RegistrationDecision::ConfirmOverwrite => Err(crate::Error::build_invalid_operation_error(
            "Registration confirmation is required before finalizing".to_string(),
        )),
    }
}

pub fn evaluate_registration_decision(
    command: &RegistrationCommand,
    force: bool,
    prompt_available: bool,
) -> Result<RegistrationDecision> {
    match command.active_membership {
        ActiveMembershipState::SameKey => {
            return Ok(RegistrationDecision::Return(
                RegistrationResult::AlreadyExists,
            ));
        }
        ActiveMembershipState::None | ActiveMembershipState::DifferentKey => {}
    }

    if !command.conflict_exists {
        return Ok(RegistrationDecision::Apply { overwrite: force });
    }

    if force {
        return Ok(RegistrationDecision::Apply { overwrite: true });
    }

    if prompt_available {
        return Ok(RegistrationDecision::ConfirmOverwrite);
    }

    match command.mode {
        RegistrationMode::Init => Ok(RegistrationDecision::Return(RegistrationResult::Skipped)),
        RegistrationMode::Join => Err(crate::Error::build_invalid_operation_error(format!(
            "Member '{}' already exists. Use --force to overwrite.",
            command.setup.member_handle
        ))),
    }
}

fn build_registration_outcome(
    command: &RegistrationCommand,
    result: RegistrationResult,
) -> RegistrationOutcome {
    RegistrationOutcome {
        mode: command.mode,
        workspace_path: command.workspace_path.clone(),
        target: command.target,
        is_new_workspace: command.is_new_workspace,
        member_handle: command.setup.member_handle.clone(),
        key_result: command.setup.key_result.clone(),
        result,
    }
}

fn ensure_registration_member_setup(
    common: &CommonCommandOptions,
    member_handle: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<MemberSetupResult> {
    match key_plan {
        RegistrationKeyPlan::UseExisting { kid, expires_at } => {
            Ok(build_existing_member_setup(member_handle, kid, expires_at))
        }
        RegistrationKeyPlan::GenerateNew => resolve_generated_member_setup(
            common,
            &member_handle,
            github_user,
            require_generation_ssh_context(ssh_ctx)?,
        ),
    }
}

fn resolve_generated_member_setup(
    common: &CommonCommandOptions,
    member_handle: &str,
    github_user: Option<String>,
    ssh_ctx: SshSigningContextResolution,
) -> Result<MemberSetupResult> {
    let github_account = resolve_github_account(github_user, common.debug)?;
    let github_verification =
        resolve_github_verification(&ssh_ctx.public_key, github_account.as_ref(), common.debug)?;
    let key_result = generate_member_key_result(
        common,
        member_handle,
        github_account,
        github_verification,
        ssh_ctx,
    )?;

    Ok(build_generated_member_setup(member_handle, key_result))
}

fn build_existing_member_setup(
    member_handle: String,
    kid: String,
    expires_at: String,
) -> MemberSetupResult {
    MemberSetupResult {
        member_handle,
        key_result: build_existing_member_key_result(kid, expires_at),
    }
}

fn resolve_registration_context(
    common: &CommonCommandOptions,
    mode: RegistrationMode,
    setup: MemberSetupResult,
) -> Result<RegistrationCommand> {
    let paths = resolve_registration_paths(common, mode, &setup.member_handle)?;
    let active_membership = resolve_active_membership_state(
        mode,
        &paths.workspace_path,
        &setup.member_handle,
        setup.kid(),
    )?;
    Ok(RegistrationCommand {
        mode,
        workspace_path: paths.workspace_path,
        keystore_root: paths.keystore_root,
        setup,
        target: paths.target,
        is_new_workspace: paths.is_new_workspace,
        conflict_exists: paths.conflict_exists,
        active_membership,
    })
}

fn resolve_github_verification(
    ssh_public_key: &str,
    github_account: Option<&GithubAccount>,
    verbose: bool,
) -> Result<OnlineVerificationStatus> {
    match github_account {
        Some(account) => verify_preflight_github_binding(ssh_public_key, account, verbose),
        None => Ok(OnlineVerificationStatus::NotConfigured),
    }
}

fn generate_member_key_result(
    common: &CommonCommandOptions,
    member_handle: &str,
    github_account: Option<GithubAccount>,
    github_verification: OnlineVerificationStatus,
    ssh_ctx: SshSigningContextResolution,
) -> Result<MemberKeySetupResult> {
    let (created_at, expires_at) = resolve_key_timestamps(&None, &None)?;
    let result = generate_and_save_key(AppKeyGenerationOptions {
        member_handle: member_handle.to_string(),
        home: common.home.clone(),
        created_at,
        expires_at,
        no_activate: false,
        debug: common.debug,
        github_account,
        github_verification,
        ssh_ctx,
    })?;
    Ok(MemberKeySetupResult {
        kid: result.kid,
        created: true,
        expires_at: result.expires_at,
        ssh_fingerprint: Some(result.ssh_fingerprint),
        ssh_determinism: Some(result.ssh_determinism),
        github_verification: result.github_verification,
    })
}

fn build_generated_member_setup(
    member_handle: &str,
    key_result: MemberKeySetupResult,
) -> MemberSetupResult {
    MemberSetupResult {
        member_handle: member_handle.to_string(),
        key_result,
    }
}

fn build_existing_member_key_result(kid: String, expires_at: String) -> MemberKeySetupResult {
    MemberKeySetupResult {
        kid,
        created: false,
        expires_at,
        ssh_fingerprint: None,
        ssh_determinism: None,
        github_verification: OnlineVerificationStatus::NotConfigured,
    }
}

fn require_generation_ssh_context(
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<SshSigningContextResolution> {
    ssh_ctx.ok_or_else(|| {
        crate::Error::build_invalid_operation_error(
            "SSH signing context is required for key generation".to_string(),
        )
    })
}
