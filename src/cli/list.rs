// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! list command - list all keys in default kv-enc file

use clap::Args;

use crate::cli::common::command::ReadCommandLabels;
use crate::cli::common::kv_read::{KvReadSession, NonMemberReviewMode};
use crate::cli::common::output::kv::print_kv_key_list;
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, KvStoreNameOption, MemberHandleOption,
    SigningOutputOptions,
};
use kapsaro_core::api::kv::KvReadOperation;
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
    let session = KvReadSession::open(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        NonMemberReviewMode::Configured(args.allow_non_member.allow_non_member),
        args.store.name.as_deref(),
        args.member.member_handle.clone(),
    )?;
    let keys_with_disclosed = session
        .authorize(
            KvReadOperation::List,
            ReadCommandLabels {
                context: "list signer",
                allow_non_member: session.allow_non_member(),
            },
        )?
        .into_value()
        .list_entry_keys()?;
    print_kv_key_list(&keys_with_disclosed, args.common.json.json)
}
