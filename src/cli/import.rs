// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! import command - import .env file into kv-enc secrets

use clap::Args;

use crate::cli::common::command::{
    open_cli_write_session, run_kv_write_command_with_recovery, CliWriteSession, WriteCommandLabels,
};
use crate::cli::common::context::CliContext;
use crate::cli::common::output::kv::print_kv_import_result;
use crate::cli::common::trust::confirm_recipient_set_approval;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningQuietOutputOptions,
};
use kapsaro_core::api::kv::load_import_text;
use kapsaro_core::api::kv::mutation::import_kv_command_with_recipient_set_confirmation;
use kapsaro_core::Result;

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
    let content = load_import_text(std::path::Path::new(&args.filename))?;
    let context = CliContext::resolve(&args.common)?;
    let allow_expired_key = context.allow_expired_key(args.allow_expired_key.allow_expired_key)?;
    let session = open_cli_write_session(
        &context,
        args.member.member_handle.clone(),
        allow_expired_key,
    )?;
    let entry_count = import_entries(&session, args.store.name.as_deref(), &content)?;

    print_kv_import_result(
        entry_count,
        args.store.name.as_deref().unwrap_or("default"),
        args.common.json.json,
        args.common.quiet.quiet,
    )
}

fn import_entries(
    session: &CliWriteSession,
    store_name: Option<&str>,
    content: &str,
) -> Result<usize> {
    run_kv_write_command_with_recovery(
        session,
        store_name,
        true,
        WriteCommandLabels {
            signer_context: Some(("import input signer", "input signer")),
            recipient_context: "import recipients",
        },
        |trust_plan| {
            import_kv_command_with_recipient_set_confirmation(trust_plan, content, |outcome, _| {
                confirm_recipient_set_approval(outcome)
            })
        },
    )
}
