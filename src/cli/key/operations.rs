// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key operations (activate, remove, export) implementation

use crate::cli::common::command::resolve_required_cli_member_handle;
use crate::cli::common::context::CliContext;
use crate::cli::common::key_context::load_trust_command_session;
use crate::cli::common::output::text::key::{
    print_key_activate_summary, print_key_export_summary, print_key_remove_summary,
    print_private_key_export_file_summary, print_private_key_export_stdout_summary,
};
use crate::cli::common::output::text::print_warning;
use crate::cli::common::output::text::trust::{
    print_trust_store_resigned, print_trust_store_signer_notice,
};
use kapsaro_core::api::key::manage::{
    activate_key_command, export_key_command, export_private_key_command, remove_key_command,
};
use kapsaro_core::api::key::types::KeyExportPrivateResult;
use kapsaro_core::api::key::{save_private_export_text, Kid, MemberHandle};
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::Result;
use std::io::IsTerminal;
use std::io::{self, BufRead};
use std::path::PathBuf;
use zeroize::Zeroizing;

use super::{ActivateArgs, ExportArgs, RemoveArgs};

/// Main entry point for key activation
pub(super) fn run_activate(args: ActivateArgs) -> Result<()> {
    let context = CliContext::resolve(&args.common)?;
    let member_handle = context.member_handle(args.member.member_handle.clone())?;
    let result = activate_key_command(context.base_dir()?, member_handle, args.kid.clone())?;
    print_key_activate_summary(&result.member_handle, &result.kid);
    if let Some(warning) = result.trust_store_warning.as_deref() {
        print_warning(warning);
    }
    if let Some(signer_kid) = result
        .trust_store_signer_kid
        .as_deref()
        .filter(|signer_kid| *signer_kid != result.kid)
    {
        print_trust_store_signer_notice(signer_kid, &result.member_handle);
    }
    Ok(())
}

/// Main entry point for key removal
pub(super) fn run_remove(args: RemoveArgs) -> Result<()> {
    let context = CliContext::resolve(&args.common)?;
    let member_handle = context.member_handle(args.member.member_handle.clone())?;
    let result = remove_key_command(
        context.base_dir()?,
        member_handle,
        args.kid.clone(),
        args.force.force,
        |member_handle| {
            load_trust_command_session(
                &context,
                &args.common,
                Some(member_handle.as_str().to_string()),
            )
        },
    )?;
    print_key_remove_summary(&result.member_handle, &result.kid, result.was_active);
    if let Some(signer_kid) = result.resigned_trust_store_kid.as_deref() {
        print_trust_store_resigned(signer_kid);
    }
    if let Some(warning) = result.trust_store_warning.as_deref() {
        print_warning(warning);
    }
    Ok(())
}

/// Main entry point for public key export
pub(super) fn run_export(args: ExportArgs) -> Result<()> {
    let out = args.out.as_ref().ok_or_else(|| {
        kapsaro_core::Error::build_invalid_argument_error(
            "--out is required for public key export".to_string(),
        )
    })?;
    let context = CliContext::resolve(&args.common)?;
    let member_handle = context.member_handle(args.member.member_handle.clone())?;
    let result = export_key_command(context.base_dir()?, member_handle, args.kid.clone(), out)?;
    print_key_export_summary(&result.member_handle, &result.kid, out);

    Ok(())
}

/// Main entry point for private key export (password-protected portable format)
pub(super) fn run_export_private(args: ExportArgs) -> Result<()> {
    let destination = ensure_private_export_destination(&args)?;

    let context = CliContext::resolve(&args.common)?;
    let member_handle =
        resolve_required_cli_member_handle(&context, args.member.member_handle.clone(), false)?;
    let member = MemberHandle::try_from(member_handle.clone())?;
    let requested_kid = args.kid.clone().map(Kid::try_from).transpose()?;
    let store = context.local_state()?.require_key_store(&member)?;
    let ssh_inputs = context.ssh_signing_inputs()?;
    let (selected_kid, ssh_ctx) =
        store.resolve_signing_context(member, requested_kid, &ssh_inputs, false)?;
    let password = prompt_export_password()?;

    let result = export_private_key_command(
        context.base_dir()?,
        member_handle,
        Some(selected_kid.into_string()),
        &password,
        args.allow_weak_password,
        ssh_ctx,
    )?;

    if let Some(warning) = result.password_warning.as_deref() {
        print_warning(warning);
    }

    write_private_key_export(destination, &result)
}

/// Where a private key export lands, per the `--out` / `--stdout` invariant:
/// exactly one of the two must be named by the operator.
enum Destination {
    File(PathBuf),
    Stdout,
}

/// An export has to land somewhere the operator named.
fn ensure_private_export_destination(args: &ExportArgs) -> Result<Destination> {
    if let Some(out) = args.out.as_ref() {
        return Ok(Destination::File(out.clone()));
    }
    if args.stdout {
        return Ok(Destination::Stdout);
    }
    Err(kapsaro_core::Error::build_invalid_argument_error(
        "--private export requires either --out or --stdout".to_string(),
    ))
}

/// Deliver the exported key to the destination the operator named.
fn write_private_key_export(
    destination: Destination,
    result: &KeyExportPrivateResult,
) -> Result<()> {
    match destination {
        Destination::File(out) => {
            save_private_export_text(&out, result.encoded_key.as_str())?;
            print_private_key_export_file_summary(&result.member_handle, &result.kid, &out);
        }
        Destination::Stdout => {
            eprintln!();
            println!("{}", result.encoded_key.as_str());
            print_private_key_export_stdout_summary(&result.member_handle, &result.kid);
        }
    }
    Ok(())
}

fn prompt_export_password() -> Result<SecretString> {
    if io::stdin().is_terminal() {
        return prompt_export_password_interactively();
    }
    read_export_password_from_stdin()
}

fn prompt_export_password_interactively() -> Result<SecretString> {
    let password = dialoguer::Password::new()
        .with_prompt("Enter password for key export")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()
        .map_err(|e| {
            kapsaro_core::Error::build_io_error(format!("Failed to read password: {}", e))
        })?;
    Ok(SecretString::new(password))
}

/// Read the password and its confirmation from a piped stdin.
fn read_export_password_from_stdin() -> Result<SecretString> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut password = Zeroizing::new(String::new());
    let mut confirmation = Zeroizing::new(String::new());

    reader.read_line(&mut password).map_err(|e| {
        kapsaro_core::Error::build_io_error(format!("Failed to read password: {}", e))
    })?;
    reader.read_line(&mut confirmation).map_err(|e| {
        kapsaro_core::Error::build_io_error(format!("Failed to read password confirmation: {}", e))
    })?;

    normalize_line_ending(&mut password);
    normalize_line_ending(&mut confirmation);

    if password.as_str() != confirmation.as_str() {
        return Err(kapsaro_core::Error::build_invalid_argument_error(
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
