// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! list command - list all keys in default kv-enc file

use clap::Args;

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::kv::print_kv_key_list;
use crate::cli::options::{KvStoreNameOption, WorkspaceOutputOptions};
use secretenv_core::cli_api::app::kv::query::list_kv_command;
use secretenv_core::Result;

#[derive(Args)]
pub struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: WorkspaceOutputOptions,

    #[command(flatten)]
    pub store: KvStoreNameOption,
}

pub fn run(args: ListArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let keys_with_disclosed = list_kv_command(&options, args.store.name.as_deref())?;
    print_kv_key_list(&keys_with_disclosed, args.common.json.json)
}
