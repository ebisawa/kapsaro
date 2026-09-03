// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key listing (key list) implementation

use crate::cli::common::context::CliContext;
use crate::cli::common::output::key::print_key_list;
use kapsaro_core::api::key::manage::list_keys_command;
use kapsaro_core::Result;

use super::ListArgs;

/// Main entry point for key listing
pub(super) fn run(args: ListArgs) -> Result<()> {
    let context = CliContext::resolve(&args.common)?;
    let result = list_keys_command(context.base_dir()?, args.member.member_handle.clone())?;
    print_key_list(args.common.json.json, &result, args.common.verbose.verbose)
}
