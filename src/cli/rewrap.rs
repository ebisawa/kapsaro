// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! rewrap command - recipient management for encrypted files

use crate::cli::common::context::CliContext;
use crate::cli::common::key_context::load_trust_command_session;
use crate::cli::common::presentation::tty;
use crate::cli::common::trust::run_with_trust_command_session_reset_recovery;
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, MemberHandleOption, SigningQuietOutputOptions,
};
use clap::Args;
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::rewrap::RewrapSession;
use kapsaro_core::{Error, Result};
use std::path::PathBuf;

mod batch;
mod promotion;

#[derive(Args, Clone)]
pub(crate) struct RewrapArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub allow_non_member: AllowNonMemberOption,

    /// Clear removed_recipients history
    #[arg(long)]
    pub clear_disclosure_history: bool,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Rotate content key (full re-encryption)
    #[arg(long)]
    pub rotate_key: bool,

    /// Explicit encrypted artifact path to rewrap; when specified, only these files are processed
    #[arg(long = "target", value_name = "path")]
    pub targets: Vec<PathBuf>,
}

pub(crate) fn run(args: RewrapArgs) -> Result<()> {
    let context = CliContext::resolve(&args.common)?;
    enforce_rewrap_strict_key_checking(&context)?;
    let workspace = context.workspace_path()?;
    let allow_expired_key = context.allow_expired_key(args.allow_expired_key.allow_expired_key)?;
    let allow_non_member = context.allow_non_member(args.allow_non_member.allow_non_member)?;
    let trust_session = load_trust_command_session(&context, args.member.member_handle.clone())?;
    let session = RewrapSession::from_trust_command(&workspace, &trust_session)?;
    let operation = OperationOptions::new().with_allow_expired_key(allow_expired_key);

    run_with_trust_command_session_reset_recovery(&trust_session, || {
        batch::run_batch_rewrap(
            &args,
            &session,
            operation,
            allow_non_member,
            tty::is_interactive(),
        )
    })
}

fn enforce_rewrap_strict_key_checking(context: &CliContext) -> Result<()> {
    if !context.strict_key_checking()?.is_disabled() {
        return Ok(());
    }
    Err(Error::build_invalid_operation_error(
        "KAPSARO_STRICT_KEY_CHECKING=no is not allowed for rewrap".to_string(),
    ))
}
