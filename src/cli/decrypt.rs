// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! decrypt command - file-enc decryption

use clap::Args;
use std::io;
use std::path::PathBuf;

use crate::cli::common::command::{
    ensure_reviewed_artifact_unchanged, resolve_options_with_read_trust_allowances,
    run_read_command_with_recovery, ReadCommandContext, ReadCommandLabels,
};
use crate::cli::common::output::file::{resolve_decrypted_output_path, save_decrypted_output};
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, MemberHandleOption, SigningQuietOptions,
};
use kapsaro_core::api::file::FileEncArtifact;
use kapsaro_core::api::trust::TrustDecision;
use kapsaro_core::cli_api::app::context::execution::{
    resolve_read_execution, resolve_read_trust_evaluator,
};
use kapsaro_core::cli_api::app::file::decrypt::evaluate_decrypt_file_trust_plan;
use kapsaro_core::cli_api::app::trust::evaluate_file_after_cli_review;
use kapsaro_core::{Error, Result};

#[derive(Args)]
#[command(
    override_usage = "kapsaro decrypt [OPTIONS] <INPUT> (--out <OUT> | --stdout)\n       kapsaro decrypt [OPTIONS] --stdin (--out <OUT> | --stdout)"
)]
pub(crate) struct DecryptArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub allow_non_member: AllowNonMemberOption,

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

pub(crate) fn run(args: DecryptArgs) -> Result<()> {
    let artifact = load_decrypt_artifact(args.input.as_ref(), args.stdin)?;
    let output_path = resolve_decrypted_output_path(args.out.as_ref(), args.stdout)?;
    let options = resolve_options_with_read_trust_allowances(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        args.allow_non_member.allow_non_member,
    )?;
    let verified = artifact.verify(options.operation_options())?;
    let plaintext_bytes = run_read_command_with_recovery(
        &options,
        args.member.member_handle.clone(),
        ReadCommandLabels {
            context: "decrypt signer",
            subject: "signer",
            workspace_purpose: "decrypt",
            allow_non_member: options.allow_non_member,
        },
        |ssh_ctx| {
            let execution = resolve_read_execution(
                &options,
                args.member.member_handle.clone(),
                args.kid.as_deref(),
                ssh_ctx,
            )?;
            let trust = evaluate_decrypt_file_trust_plan(&options, &execution, &verified)?;
            Ok(ReadCommandContext::new(execution, trust))
        },
        |context| {
            let evaluator = resolve_read_trust_evaluator(&options, &context.execution)?;
            if args.stdin {
                return decrypt_after_review(&evaluator, &verified, &verified, context, &options);
            }
            let current_artifact = load_decrypt_artifact(args.input.as_ref(), false)?;
            ensure_reviewed_artifact_unchanged(
                artifact.as_str(),
                current_artifact.as_str(),
                "decrypt authorization",
            )?;
            let current = current_artifact.verify(options.operation_options())?;
            decrypt_after_review(&evaluator, &verified, &current, context, &options)
        },
    )?;

    save_decrypted_output(
        output_path.as_deref(),
        plaintext_bytes.expose_secret(),
        args.common.quiet.quiet,
    )?;
    Ok(())
}

fn decrypt_after_review(
    evaluator: &kapsaro_core::api::trust::TrustPolicyEvaluator,
    reviewed: &kapsaro_core::api::file::VerifiedFileEncArtifact,
    current: &kapsaro_core::api::file::VerifiedFileEncArtifact,
    context: &ReadCommandContext,
    options: &kapsaro_core::cli_api::app::context::options::CommonCommandOptions,
) -> Result<kapsaro_core::api::secret::SecretBytes> {
    match evaluate_file_after_cli_review(
        evaluator,
        reviewed,
        current,
        &context.execution.key_ctx,
        context.signer_outcome(),
        options.operation_options(),
    )? {
        TrustDecision::Trusted(trusted) => trusted.decrypt_bytes(),
        TrustDecision::ReviewRequired(_) => Err(Error::build_verification_error(
            "E_TRUST_REVIEW_REQUIRED".to_string(),
            "Trust state changed while reviewing the file artifact".to_string(),
        )),
    }
}

fn load_decrypt_artifact(
    input_path: Option<&PathBuf>,
    from_stdin: bool,
) -> Result<FileEncArtifact> {
    if from_stdin {
        return FileEncArtifact::load_reader(io::stdin().lock(), "stdin");
    }

    input_path
        .map(FileEncArtifact::load)
        .transpose()?
        .ok_or_else(|| {
            Error::build_invalid_argument_error("INPUT is required unless --stdin is used")
        })
}
