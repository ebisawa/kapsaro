// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! import command - import .env file into kv-enc secrets

use clap::Args;

use crate::app::kv::mutation::import_kv_command;
use crate::app::trust::ImportPolicy;
use crate::cli::common::command::{
    resolve_options, resolve_trust_store_owner_member, run_kv_write_command_with_trust,
    WriteCommandLabels,
};
use crate::cli::common::output::kv::print_kv_import_result;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::CommonOptions;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_KV_ENC_FILE_SIZE;
use crate::Result;

#[derive(Args)]
pub struct ImportArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_handle: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

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
        || resolve_trust_store_owner_member(&options, args.member_handle.clone()),
        || {
            run_kv_write_command_with_trust::<ImportPolicy, _, _>(
                &args.common,
                args.member_handle.clone(),
                args.name.as_deref(),
                true,
                WriteCommandLabels {
                    signer_context: Some(("import input signer", "input signer")),
                    recipient_context: "import recipients",
                },
                |_, trust_plan| import_kv_command(trust_plan, &content, None),
            )
        },
    )?;

    print_kv_import_result(
        outcome.message.as_deref(),
        entry_count,
        args.name.as_deref().unwrap_or("default"),
        args.common.json,
        args.common.quiet,
    )
}
