// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key operations (activate, remove, export) implementation

use crate::cli::common::command::{
    resolve_options, resolve_required_member_handle, resolve_write_execution_input,
};
use crate::cli::common::output::text::key::{
    print_key_activate_summary, print_key_export_summary, print_key_remove_summary,
    print_private_key_export_file_summary, print_private_key_export_stdout_summary,
};
use crate::cli::common::output::text::print_warning;
use crate::cli::common::output::text::trust::{
    print_trust_store_resigned, print_trust_store_signer_notice,
};
use kapsaro_core::api::key::MemberHandle;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::cli_api::app::context::execution::ExecutionContext;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::context::ssh::resolve_ssh_context_for_member_key;
use kapsaro_core::cli_api::app::key::manage::{
    activate_key_command, export_key_command, export_private_key_command, remove_key_command,
    validate_kid,
};
use kapsaro_core::cli_api::app::key::types::KeyExportPrivateResult;
use kapsaro_core::cli_api::presentation::fs::save_text_restricted;
use kapsaro_core::Result;
use std::io::IsTerminal;
use std::io::{self, BufRead};
use std::path::PathBuf;
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
    let options = resolve_options(&args.common);
    let result = remove_key_command(
        &options,
        args.member.member_handle.clone(),
        args.kid.clone(),
        args.force.force,
        |member_handle| resolve_removal_signing_execution(&options, member_handle),
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

/// Resolve the signing identity the trust store hand-over needs.
///
/// The identity is resolved here rather than up front, so a removal that leaves
/// the signature alone never asks for an SSH key. The hand-over itself is run by
/// the command, which is what decides whether the removal may go on.
fn resolve_removal_signing_execution(
    options: &CommonCommandOptions,
    member_handle: &MemberHandle,
) -> Result<ExecutionContext> {
    resolve_write_execution_input(options, Some(member_handle.as_str().to_string()))
}

/// Main entry point for public key export
pub(super) fn run_export(args: ExportArgs) -> Result<()> {
    let out = args.out.as_ref().ok_or_else(|| {
        kapsaro_core::Error::build_invalid_argument_error(
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
    let destination = ensure_private_export_destination(&args)?;

    let options = resolve_options(&args.common);
    let member_handle =
        resolve_required_member_handle(&options, args.member.member_handle.clone(), false)?;
    // When no kid is given, the active key is resolved three separate times: to
    // check it exists, to pick the SSH context that unwraps it, and again inside
    // the export. A `key activate` landing while the password prompt is open can
    // move the selection in between, so the export either fails to decrypt
    // against a context resolved for the previous key or exports the newly
    // activated one. This is accepted: no operator confirmation is skipped, the
    // summary names the kid that was actually exported, and every key reachable
    // this way is one this member already holds.
    validate_kid(&options, &member_handle, args.kid.clone())?;
    // The named key travels to the SSH context as well, so the identity that
    // unwraps the export is the one that protects the key being exported rather
    // than the one that protects whichever key is active.
    let ssh_ctx = resolve_ssh_context_for_member_key(
        &options,
        Some(member_handle.clone()),
        args.kid.as_deref(),
    )?;
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
            save_text_restricted(&out, result.encoded_key.as_str())?;
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
