// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! import command - import .env file into kv-enc secrets

use clap::Args;

use crate::cli::common::command::{
    resolve_options, resolve_trust_store_owner_member, run_kv_write_command_with_trust,
    WriteCommandLabels,
};
use crate::cli::common::output::kv::print_kv_import_result;
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::trust::{
    confirm_recipient_set_approval, run_with_trust_store_reset_recovery,
};
use crate::cli::options::{KvStoreNameOption, MemberHandleOption, SigningQuietOutputOptions};
use secretenv_core::cli_api::app::kv::mutation::import_kv_command_with_recipient_set_confirmation;
use secretenv_core::cli_api::app::trust::ImportPolicy;
use secretenv_core::cli_api::presentation::fs::load_text_with_limit;
use secretenv_core::cli_api::presentation::limits::MAX_KV_ENC_FILE_SIZE;
use secretenv_core::Result;

#[derive(Args)]
pub struct ImportArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOutputOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// File to import (.env format)
    pub filename: String,
}

pub fn run(args: ImportArgs) -> Result<()> {
    let content = load_text_with_limit(
        std::path::Path::new(&args.filename),
        MAX_KV_ENC_FILE_SIZE,
        "dotenv file",
    )?;
    let options = resolve_options(&args.common);
    let (outcome, entry_count) = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || {
            run_kv_write_command_with_trust::<ImportPolicy, _, _>(
                &args.common,
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
