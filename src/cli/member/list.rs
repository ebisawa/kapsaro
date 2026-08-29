// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI entry point for `member list`.
//! Loads the workspace members and renders them as text or JSON per the caller's flag.

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::member::print_member_list;
use kapsaro_core::cli_api::app::member::query::list_members;
use kapsaro_core::Error;

use super::ListArgs;

pub(crate) fn run(args: ListArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let result = list_members(&options)?;
    print_member_list(args.common.json.json, &result)
}
