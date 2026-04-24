// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key listing (key list) implementation

use crate::app::key::manage::list_keys_command;
use crate::cli::common::command::resolve_options;
use crate::cli::common::output::key::print_key_list;
use crate::Result;

use super::ListArgs;

/// Main entry point for key listing
pub fn run(args: ListArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let result = list_keys_command(&options, args.member_handle.clone())?;
    print_key_list(args.common.json, &result, args.common.verbose)
}
