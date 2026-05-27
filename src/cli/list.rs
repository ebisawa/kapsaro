// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! list command - list all keys in default kv-enc file

use clap::Args;

use crate::cli::common::command::{
    resolve_options_with_read_trust_allowances, run_read_command_with_recovery, ReadCommandLabels,
};
use crate::cli::common::output::kv::print_kv_key_list;
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, KvStoreNameOption, MemberHandleOption,
    SigningOutputOptions,
};
use secretenv_core::cli_api::app::kv::query::{execute_kv_list_command, resolve_kv_read_command};
use secretenv_core::cli_api::app::trust::ListPolicy;
use secretenv_core::Result;

#[derive(Args)]
pub(crate) struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub allow_non_member: AllowNonMemberOption,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,
}

pub(crate) fn run(args: ListArgs) -> Result<()> {
    let options = resolve_options_with_read_trust_allowances(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        args.allow_non_member.allow_non_member,
    )?;
    let keys_with_disclosed = run_read_command_with_recovery(
        &options,
        args.member.member_handle.clone(),
        ReadCommandLabels {
            context: "list signer",
            subject: "signer",
            allow_non_member: options.allow_non_member,
        },
        |ssh_ctx| {
            resolve_kv_read_command::<ListPolicy>(
                &options,
                args.member.member_handle.clone(),
                args.store.name.as_deref(),
                ssh_ctx,
            )
        },
        |command| execute_kv_list_command(command, args.common.debug.debug),
    )?;
    print_kv_key_list(&keys_with_disclosed, args.common.json.json)
}
