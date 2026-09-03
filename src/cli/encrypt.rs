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
    resolve_cli_write_session, run_write_command_with_trust, CliWriteSession, WriteCommandLabels,
};
use crate::cli::common::context::CliContext;
use crate::cli::common::output::file::{resolve_encrypted_output_path, save_encrypted_output};
use crate::cli::common::trust::{
    confirm_recipient_set_approval, run_with_trust_command_session_reset_recovery,
};
use crate::cli::options::{MemberHandleOption, SigningQuietOptions};
use kapsaro_core::api::file::encrypt::{
    execute_encrypt_file_command_with_recipient_set_confirmation, resolve_encrypt_file_command,
};
use kapsaro_core::api::file::load_plaintext_bytes;
use kapsaro_core::api::workspace::WorkspaceWriteDirectories;
use kapsaro_core::{Error, Result};

#[derive(Args)]
#[command(
    override_usage = "kapsaro encrypt [OPTIONS] <INPUT>\n       kapsaro encrypt [OPTIONS] --stdin (--out <path> | --stdout)"
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
    let context = CliContext::resolve(&args.common)?;
    let workspace_path = context.workspace_path()?;
    let directories = WorkspaceWriteDirectories::open(workspace_path)?;
    let session = resolve_cli_write_session(
        &context,
        &args.common,
        directories,
        args.member.member_handle.clone(),
        false,
    )?;
    let encrypted = encrypt_under_trust_review(&session, &input_bytes)?;

    save_encrypted_output(output_path.as_ref(), &encrypted, args.common.quiet.quiet)?;
    Ok(())
}

fn encrypt_under_trust_review(session: &CliWriteSession, input_bytes: &[u8]) -> Result<String> {
    run_with_trust_command_session_reset_recovery(session.trust(), || {
        let command = resolve_encrypt_file_command(
            session.directories(),
            session.trust(),
            session.options(),
            input_bytes.to_vec(),
        )?;
        run_write_command_with_trust(
            &command,
            WriteCommandLabels {
                signer_context: None,
                recipient_context: "encrypt recipients",
            },
            || {
                execute_encrypt_file_command_with_recipient_set_confirmation(
                    &command,
                    confirm_recipient_set_approval,
                )
            },
        )
    })
}

fn resolve_encrypt_input_bytes(input_path: Option<&PathBuf>, from_stdin: bool) -> Result<Vec<u8>> {
    if from_stdin {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        return Ok(bytes);
    }

    input_path
        .map(load_plaintext_bytes)
        .transpose()?
        .ok_or_else(|| {
            Error::build_invalid_argument_error("INPUT is required unless --stdin is used")
        })
}
