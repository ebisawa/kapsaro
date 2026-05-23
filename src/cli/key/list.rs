// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key listing (key list) implementation

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::key::print_key_list;
use secretenv_core::cli_api::app::key::manage::list_keys_command;
use secretenv_core::Result;

use super::ListArgs;

/// Main entry point for key listing
pub(super) fn run(args: ListArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let result = list_keys_command(&options, args.member.member_handle.clone())?;
    print_key_list(args.common.json.json, &result, args.common.verbose.verbose)
}
