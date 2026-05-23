// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! encrypt command implementation
//!
//! Encrypts a plain file to file-enc format with automatic signing.
//! Recipients are always all active workspace members.

use clap::Args;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::cli::common::command::{
    resolve_options, resolve_trust_store_owner_member, run_write_command_with_trust,
    WriteCommandLabels,
};
use crate::cli::common::output::file::{resolve_encrypted_output_path, save_encrypted_output};
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::cli::common::trust::{
    confirm_recipient_set_approval, run_with_trust_store_reset_recovery,
};
use crate::cli::options::{MemberHandleOption, SigningQuietOptions};
use secretenv_core::cli_api::app::file::encrypt::{
    execute_encrypt_file_command_with_recipient_set_confirmation, resolve_encrypt_file_command,
};
use secretenv_core::cli_api::presentation::fs::load_bytes;
use secretenv_core::{Error, Result};

#[derive(Args)]
#[command(
    override_usage = "secretenv encrypt [OPTIONS] <INPUT>\n       secretenv encrypt [OPTIONS] --stdin (--out <path> | --stdout)"
)]
pub(crate) struct EncryptArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Output file path
    #[arg(long, short = 'o', conflicts_with = "stdout")]
    pub out: Option<PathBuf>,

    /// Write encrypted content to stdout
    #[arg(long, conflicts_with = "out")]
    pub stdout: bool,

    /// Read input bytes from stdin
    #[arg(long, conflicts_with = "input")]
    pub stdin: bool,

    /// Input file path
    #[arg(required_unless_present = "stdin")]
    pub input: Option<PathBuf>,
}

pub(crate) fn run(args: EncryptArgs) -> Result<()> {
    let input_bytes = resolve_encrypt_input_bytes(args.input.as_ref(), args.stdin)?;
    let output_path = resolve_encrypted_output_path(
        args.out.as_ref(),
        args.stdout,
        args.input.as_deref(),
        args.stdin,
    )?;
    let options = resolve_options(&args.common);
    let (encrypted, approval_warnings) = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || {
            let ssh_ctx =
                resolve_ssh_context_optional(&options, args.member.member_handle.clone())?;
            let command = resolve_encrypt_file_command(
                &options,
                args.member.member_handle.clone(),
                input_bytes.clone(),
                ssh_ctx,
            )?;
            run_write_command_with_trust(
                &options,
                &command,
                WriteCommandLabels {
                    signer_context: None,
                    recipient_context: "encrypt recipients",
                },
                || {
                    execute_encrypt_file_command_with_recipient_set_confirmation(
                        &options,
                        &command,
                        options.debug,
                        confirm_recipient_set_approval,
                    )
                },
            )
        },
    )?;

    print_warnings(&approval_warnings);
    save_encrypted_output(output_path.as_ref(), &encrypted, args.common.quiet.quiet)?;
    Ok(())
}

fn resolve_encrypt_input_bytes(input_path: Option<&PathBuf>, from_stdin: bool) -> Result<Vec<u8>> {
    if from_stdin {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        return Ok(bytes);
    }

    input_path
        .map(|path| load_bytes(path))
        .transpose()?
        .ok_or_else(|| {
            Error::build_invalid_argument_error("INPUT is required unless --stdin is used")
        })
}
