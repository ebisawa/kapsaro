// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! decrypt command - file-enc decryption

use clap::Args;
use std::path::PathBuf;

use crate::app::file::decrypt::{build_decrypt_file_command, execute_decrypt_file_command};
use crate::cli::common::command::{
    resolve_command_input, resolve_options, resolve_trust_store_owner_member,
    run_read_command_with_trust, ReadCommandLabels,
};
use crate::cli::common::output::file::save_decrypted_output;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::CommonOptions;
use crate::format::content::FileEncContent;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::{Error, Result};

#[derive(Args)]
pub struct DecryptArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Key ID to use [default: auto-select]
    #[arg(long, short = 'k')]
    pub kid: Option<String>,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Output file path (required)
    #[arg(long, short = 'o')]
    pub out: Option<PathBuf>,

    /// Input file path
    pub input: PathBuf,
}

// ============================================================================
// Main Command Implementation
// ============================================================================

pub fn run(args: DecryptArgs) -> Result<()> {
    let content = FileEncContent::detect(load_text_with_limit(
        &args.input,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "file-enc file",
    )?)?;
    // Require --out option only after the input was confirmed as file-enc.
    let out_path = args.out.as_ref().ok_or_else(|| Error::Config {
        message: "requires --out option".to_string(),
    })?;
    let options = resolve_options(&args.common);
    let plaintext_bytes = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member_id.clone()),
        || {
            let (_, ssh_ctx) = resolve_command_input(&args.common, args.member_id.clone())?;
            let command = build_decrypt_file_command(
                &options,
                args.member_id.clone(),
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

    save_decrypted_output(out_path, plaintext_bytes.as_ref(), args.common.quiet)?;
    Ok(())
}
