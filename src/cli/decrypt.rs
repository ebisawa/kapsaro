// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! decrypt command - file-enc decryption

use clap::Args;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::cli::common::command::{
    resolve_command_input, resolve_options, resolve_trust_store_owner_member,
    run_read_command_with_trust, ReadCommandLabels,
};
use crate::cli::common::output::file::{resolve_decrypted_output_path, save_decrypted_output};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::{MemberHandleOption, SigningQuietOptions};
use secretenv_core::cli_api::app::file::decrypt::{
    execute_decrypt_file_command, resolve_decrypt_file_command,
};
use secretenv_core::cli_api::presentation::file_content::detect_file_enc_content_with_source;
use secretenv_core::cli_api::presentation::fs::load_text_with_limit;
use secretenv_core::cli_api::presentation::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use secretenv_core::cli_api::presentation::path::format_path_relative_to_cwd;
use secretenv_core::{Error, Result};

#[derive(Args)]
#[command(
    override_usage = "secretenv decrypt [OPTIONS] <INPUT> (--out <OUT> | --stdout)\n       secretenv decrypt [OPTIONS] --stdin (--out <OUT> | --stdout)"
)]
pub struct DecryptArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOptions,

    /// Key ID to use [default: auto-select]
    #[arg(long, short = 'k')]
    pub kid: Option<String>,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Output file path
    #[arg(long, short = 'o', conflicts_with = "stdout")]
    pub out: Option<PathBuf>,

    /// Write decrypted content to stdout
    #[arg(long, conflicts_with = "out")]
    pub stdout: bool,

    /// Read encrypted content from stdin
    #[arg(long, conflicts_with = "input")]
    pub stdin: bool,

    /// Input file path
    #[arg(required_unless_present = "stdin")]
    pub input: Option<PathBuf>,
}

// ============================================================================
// Main Command Implementation
// ============================================================================

pub fn run(args: DecryptArgs) -> Result<()> {
    let source_name = resolve_decrypt_input_source(args.input.as_ref(), args.stdin);
    let content = detect_file_enc_content_with_source(
        resolve_decrypt_input_content(args.input.as_ref(), args.stdin)?,
        source_name,
    )?;
    let output_path = resolve_decrypted_output_path(args.out.as_ref(), args.stdout)?;
    let options = resolve_options(&args.common);
    let plaintext_bytes = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || {
            let (_, ssh_ctx) =
                resolve_command_input(&args.common, args.member.member_handle.clone())?;
            let command = resolve_decrypt_file_command(
                &options,
                args.member.member_handle.clone(),
                args.kid.as_deref(),
                content.clone(),
                ssh_ctx,
            )?;
            run_read_command_with_trust(
                &options,
                &command,
                ReadCommandLabels {
                    context: "decrypt signer",
                    subject: "signer",
                    allow_non_member: true,
                },
                || execute_decrypt_file_command(&command),
            )
        },
    )?;

    save_decrypted_output(
        output_path.as_deref(),
        plaintext_bytes.as_ref(),
        args.common.quiet.quiet,
    )?;
    Ok(())
}

fn resolve_decrypt_input_content(input_path: Option<&PathBuf>, from_stdin: bool) -> Result<String> {
    if from_stdin {
        return load_decrypt_input_from_stdin();
    }

    input_path
        .map(|path| load_text_with_limit(path, MAX_JSON_DOCUMENT_READ_SIZE, "file-enc file"))
        .transpose()?
        .ok_or_else(|| {
            Error::build_invalid_argument_error("INPUT is required unless --stdin is used")
        })
}

fn resolve_decrypt_input_source(input_path: Option<&PathBuf>, from_stdin: bool) -> String {
    if from_stdin {
        return "stdin".to_string();
    }
    input_path
        .map(|path| format_path_relative_to_cwd(path))
        .unwrap_or_else(|| "input".to_string())
}

fn load_decrypt_input_from_stdin() -> Result<String> {
    let max_bytes = MAX_JSON_DOCUMENT_READ_SIZE;
    let stdin = io::stdin();
    let mut reader = stdin.lock().take((max_bytes + 1) as u64);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;

    if bytes.len() > max_bytes {
        return Err(Error::build_parse_error(format!(
            "file-enc input exceeds maximum size limit ({} bytes > {} bytes): stdin",
            bytes.len(),
            max_bytes
        )));
    }

    String::from_utf8(bytes).map_err(|e| {
        Error::build_parse_error_with_source(format!("Failed to read stdin as UTF-8: {}", e), e)
    })
}
