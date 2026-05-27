// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key operations (activate, remove, export) implementation

use crate::cli::common::command::{resolve_options, resolve_required_member_handle};
use crate::cli::common::output::text::key::{
    print_key_activate_summary, print_key_export_summary, print_key_remove_summary,
    print_private_key_export_file_summary, print_private_key_export_stdout_summary,
};
use crate::cli::common::output::text::print_warning;
use crate::cli::common::ssh::resolve_ssh_context_for_active_key;
use secretenv_core::api::secret::SecretString;
use secretenv_core::cli_api::app::key::manage::{
    activate_key_command, export_key_command, export_private_key_command, remove_key_command,
    validate_kid,
};
use secretenv_core::cli_api::presentation::fs::save_text;
use secretenv_core::Result;
use std::io::IsTerminal;
use std::io::{self, BufRead};
use zeroize::Zeroizing;

use super::{ActivateArgs, ExportArgs, RemoveArgs};

/// Main entry point for key activation
pub(super) fn run_activate(args: ActivateArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let result = activate_key_command(
        &options,
        args.member.member_handle.clone(),
        args.kid.clone(),
    )?;
    print_key_activate_summary(&result.member_handle, &result.kid);
    Ok(())
}

/// Main entry point for key removal
pub(super) fn run_remove(args: RemoveArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let result = remove_key_command(
        &options,
        args.member.member_handle.clone(),
        args.kid.clone(),
        args.force.force,
    )?;
    print_key_remove_summary(&result.member_handle, &result.kid, result.was_active);
    Ok(())
}

/// Main entry point for public key export
pub(super) fn run_export(args: ExportArgs) -> Result<()> {
    let out = args.out.as_ref().ok_or_else(|| {
        secretenv_core::Error::build_invalid_argument_error(
            "--out is required for public key export".to_string(),
        )
    })?;
    let options = resolve_options(&args.common);
    let result = export_key_command(
        &options,
        args.member.member_handle.clone(),
        args.kid.clone(),
        out,
    )?;
    print_key_export_summary(&result.member_handle, &result.kid, out);

    Ok(())
}

/// Main entry point for private key export (password-protected portable format)
pub(super) fn run_export_private(args: ExportArgs) -> Result<()> {
    if args.out.is_none() && !args.stdout {
        return Err(secretenv_core::Error::build_invalid_argument_error(
            "--private export requires either --out or --stdout".to_string(),
        ));
    }

    let options = resolve_options(&args.common);
    let member_handle =
        resolve_required_member_handle(&options, args.member.member_handle.clone(), false)?;
    validate_kid(&options, &member_handle, args.kid.clone())?;
    let ssh_ctx = resolve_ssh_context_for_active_key(&options, Some(member_handle.clone()))?;
    let password = prompt_export_password()?;

    let result = export_private_key_command(
        &options,
        member_handle,
        args.kid.clone(),
        &password,
        args.allow_weak_password,
        ssh_ctx,
    )?;

    if let Some(warning) = result.password_warning.as_deref() {
        print_warning(warning);
    }

    if let Some(out) = args.out.as_ref() {
        save_text(out, result.encoded_key.as_str())?;
        print_private_key_export_file_summary(&result.member_handle, &result.kid, out);
    } else if args.stdout {
        eprintln!();
        println!("{}", result.encoded_key.as_str());
        print_private_key_export_stdout_summary(&result.member_handle, &result.kid);
    }

    Ok(())
}

fn prompt_export_password() -> Result<SecretString> {
    if io::stdin().is_terminal() {
        let password = dialoguer::Password::new()
            .with_prompt("Enter password for key export")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()
            .map_err(|e| {
                secretenv_core::Error::build_io_error(format!("Failed to read password: {}", e))
            })?;
        return Ok(SecretString::new(password));
    }

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut password = Zeroizing::new(String::new());
    let mut confirmation = Zeroizing::new(String::new());

    reader.read_line(&mut password).map_err(|e| {
        secretenv_core::Error::build_io_error(format!("Failed to read password: {}", e))
    })?;
    reader.read_line(&mut confirmation).map_err(|e| {
        secretenv_core::Error::build_io_error(format!(
            "Failed to read password confirmation: {}",
            e
        ))
    })?;

    normalize_line_ending(&mut password);
    normalize_line_ending(&mut confirmation);

    if password.as_str() != confirmation.as_str() {
        return Err(secretenv_core::Error::build_invalid_argument_error(
            "Passwords do not match".to_string(),
        ));
    }

    Ok(SecretString::from_zeroizing(password))
}

fn normalize_line_ending(value: &mut String) {
    while matches!(value.chars().last(), Some('\n' | '\r')) {
        value.pop();
    }
}
