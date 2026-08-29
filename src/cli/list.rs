// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! list command - list all keys in default kv-enc file

use clap::Args;

use crate::cli::common::command::{resolve_options_with_read_trust_allowances, ReadCommandLabels};
use crate::cli::common::kv_read::KvReadSession;
use crate::cli::common::output::kv::print_kv_key_list;
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, KvStoreNameOption, MemberHandleOption,
    SigningOutputOptions,
};
use kapsaro_core::api::kv::KvReadOperation;
use kapsaro_core::cli_api::app::kv::query::evaluate_kv_read_trust_plan;
use kapsaro_core::cli_api::app::trust::ListPolicy;
use kapsaro_core::Result;

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
    let session = KvReadSession::open(
        options,
        args.store.name.as_deref(),
        args.member.member_handle.clone(),
    )?;
    let keys_with_disclosed = session.read(
        ReadCommandLabels {
            context: "list signer",
            subject: "signer",
            allow_non_member: session.allow_non_member(),
        },
        "KV list authorization",
        evaluate_kv_read_trust_plan::<ListPolicy>,
        |review| review.authorize(KvReadOperation::List)?.list_entry_keys(),
    )?;
    print_kv_key_list(&keys_with_disclosed, args.common.json.json)
}
