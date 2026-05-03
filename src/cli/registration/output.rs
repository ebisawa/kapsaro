// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::registration::types::{
    MemberKeySetupResult, RegistrationOutcome, RegistrationResult, RegistrationTarget,
};
use crate::cli::common::output::text::key::{
    print_existing_key_summary, print_generated_key_summary,
};
use crate::cli::common::output::text::print_warning_line;
use crate::cli::common::output::text::registration::{
    print_created_workspace_summary, print_init_noop_summary, print_registration_next_steps,
};
use crate::cli::key::common::print_key_generation_binding_info;
use crate::support::kid::format_kid_display;
use crate::Error;
use std::path::Path;

pub(super) fn print_registration_outcome(outcome: &RegistrationOutcome) -> Result<(), Error> {
    match outcome.result {
        RegistrationResult::NewMember | RegistrationResult::Updated => {
            print_key_info(&outcome.member_handle, &outcome.key_result)?;
            if outcome.is_new_workspace {
                print_created_workspace_summary(&outcome.workspace_path);
            }
            eprintln!(
                "Added '{}' to {}/",
                outcome.member_handle,
                target_directory_name(outcome.target)
            );
            eprintln!();
            print_registration_next_steps(outcome.mode, outcome.is_new_workspace);
        }
        RegistrationResult::AlreadyExists => print_existing_member_message(outcome),
        RegistrationResult::Skipped => print_skipped_message(&outcome.member_handle),
    }
    Ok(())
}

pub(super) fn print_missing_key_notice(member_handle: &str) {
    eprintln!(
        "No local key found for '{}'. Generating a new key...",
        member_handle
    );
}

pub(super) fn print_init_noop_message(workspace_path: &Path) {
    print_init_noop_summary(workspace_path);
}

fn print_existing_member_message(outcome: &RegistrationOutcome) {
    eprintln!("Already a member of this workspace.");
    let kid_display = format_kid_display(&outcome.key_result.kid)
        .unwrap_or_else(|_| outcome.key_result.kid.clone());
    eprintln!(
        "Current key: {} (active, expires {})",
        kid_display,
        format_expiry_date(&outcome.key_result.expires_at)
    );
}

fn print_skipped_message(member_handle: &str) {
    print_warning_line(&format!(
        "Warning: Member '{}' already exists in workspace (use --force to overwrite)",
        member_handle
    ));
}

fn print_key_info(member_handle: &str, key_result: &MemberKeySetupResult) -> Result<(), Error> {
    if key_result.created {
        print_generated_key_binding_info(key_result)?;
        print_generated_key_summary(
            member_handle,
            &key_result.kid,
            format_expiry_date(&key_result.expires_at),
            false,
        );
        return Ok(());
    }

    print_existing_key_summary(member_handle, &key_result.kid);
    Ok(())
}

fn print_generated_key_binding_info(key_result: &MemberKeySetupResult) -> Result<(), Error> {
    let ssh_fingerprint =
        key_result
            .ssh_fingerprint
            .as_deref()
            .ok_or_else(|| Error::InvalidOperation {
                message: "Registration output requires an SSH fingerprint for generated keys"
                    .to_string(),
            })?;
    let ssh_determinism =
        key_result
            .ssh_determinism
            .as_ref()
            .ok_or_else(|| Error::InvalidOperation {
                message: "Registration output requires SSH determinism for generated keys"
                    .to_string(),
            })?;

    print_key_generation_binding_info(
        ssh_fingerprint,
        ssh_determinism,
        key_result.github_verification,
    )
}

fn target_directory_name(target: RegistrationTarget) -> &'static str {
    target.directory_name()
}

fn format_expiry_date(expires_at: &str) -> &str {
    expires_at.split('T').next().unwrap_or(expires_at)
}
