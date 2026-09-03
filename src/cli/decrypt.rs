// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Decrypt command orchestration and presentation.
//! Delegates artifact and trust authorization to the public read session.

use std::path::PathBuf;

use clap::Args;

use crate::cli::common::file_read::FileReadSession;
use crate::cli::common::output::file::{resolve_decrypted_output_path, save_decrypted_output};
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, MemberHandleOption, SigningQuietOptions,
};
use kapsaro_core::Result;

#[derive(Args)]
#[command(
    override_usage = "kapsaro decrypt [OPTIONS] <INPUT> (--out <OUT> | --stdout)\n       kapsaro decrypt [OPTIONS] --stdin (--out <OUT> | --stdout)"
)]
pub(crate) struct DecryptArgs {
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

pub(crate) fn run(args: DecryptArgs) -> Result<()> {
    let output_path = resolve_decrypted_output_path(args.out.as_ref(), args.stdout)?;
    let session = FileReadSession::open(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        args.allow_non_member.allow_non_member,
        args.member.member_handle.clone(),
        args.kid.as_deref(),
    )?;
    let plaintext = session.decrypt(args.input.as_ref(), args.stdin)?;

    save_decrypted_output(
        output_path.as_deref(),
        plaintext.expose_secret(),
        args.common.quiet.quiet,
    )
}
