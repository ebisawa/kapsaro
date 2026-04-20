// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! encrypt command implementation
//!
//! Encrypts a plain file to file-enc v3 format with automatic signing.
//! Recipients are always all active workspace members.

use clap::Args;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::app::file::encrypt::{build_encrypt_file_command, execute_encrypt_file_command};
use crate::cli::common::command::{
    resolve_command_input, resolve_options, resolve_trust_store_owner_member,
    run_write_command_with_trust, WriteCommandLabels,
};
use crate::cli::common::output::file::{resolve_encrypted_output_path, save_encrypted_output};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::CommonOptions;
use crate::support::fs::load_bytes;
use crate::{Error, Result};

#[derive(Args)]
#[command(
    override_usage = "secretenv encrypt [OPTIONS] <INPUT>\n       secretenv encrypt [OPTIONS] --stdin (--out <path> | --stdout)"
)]
pub struct EncryptArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

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

pub fn run(args: EncryptArgs) -> Result<()> {
    let input_bytes = resolve_encrypt_input_bytes(args.input.as_ref(), args.stdin)?;
    let output_path = resolve_encrypted_output_path(
        args.out.as_ref(),
        args.stdout,
        args.input.as_deref(),
        args.stdin,
    )?;
    let options = resolve_options(&args.common);
    let encrypted = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member_id.clone()),
        || {
            let (_, ssh_ctx) = resolve_command_input(&args.common, args.member_id.clone())?;
            let command = build_encrypt_file_command(
                &options,
                args.member_id.clone(),
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
                || execute_encrypt_file_command(&command, options.verbose),
            )
        },
    )?;

    save_encrypted_output(output_path.as_ref(), &encrypted, args.common.quiet)?;
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
        .ok_or_else(|| Error::invalid_argument("INPUT is required unless --stdin is used"))
}
