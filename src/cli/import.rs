// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! import command - import .env file into kv-enc secrets

use clap::Args;

use crate::cli::common::command::{
    resolve_options_with_allow_expired_key, run_kv_write_command_with_recovery, WriteCommandLabels,
};
use crate::cli::common::output::kv::print_kv_import_result;
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::trust::confirm_recipient_set_approval;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningQuietOutputOptions,
};
use secretenv_core::cli_api::app::kv::mutation::import_kv_command_with_recipient_set_confirmation;
use secretenv_core::cli_api::app::trust::ImportPolicy;
use secretenv_core::cli_api::presentation::fs::load_text_with_limit;
use secretenv_core::cli_api::presentation::limits::MAX_KV_ENC_FILE_SIZE;
use secretenv_core::Result;

#[derive(Args)]
pub(crate) struct ImportArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// File to import (.env format)
    pub filename: String,
}

pub(crate) fn run(args: ImportArgs) -> Result<()> {
    let content = load_text_with_limit(
        std::path::Path::new(&args.filename),
        MAX_KV_ENC_FILE_SIZE,
        "dotenv file",
    )?;
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let (outcome, entry_count) = run_kv_write_command_with_recovery::<ImportPolicy, _, _>(
        &options,
        args.member.member_handle.clone(),
        args.store.name.as_deref(),
        true,
        WriteCommandLabels {
            signer_context: Some(("import input signer", "input signer")),
            recipient_context: "import recipients",
        },
        |_, trust_plan| {
            import_kv_command_with_recipient_set_confirmation(
                trust_plan,
                &content,
                None,
                confirm_recipient_set_approval,
            )
        },
    )?;

    print_warnings(&outcome.warnings);
    print_kv_import_result(
        outcome.message.as_deref(),
        entry_count,
        args.store.name.as_deref().unwrap_or("default"),
        args.common.json.json,
        args.common.quiet.quiet,
    )
}
