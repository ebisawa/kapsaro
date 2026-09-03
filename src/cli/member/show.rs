// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI entry point for `member show`.
//! Loads a single member's details by handle and renders them as text or JSON.

use crate::cli::common::context::CliContext;
use crate::cli::common::output::member::print_member_show;
use kapsaro_core::api::member::query::load_member_show_result;
use kapsaro_core::Error;

use super::ShowArgs;

pub(crate) fn run(args: ShowArgs) -> Result<(), Error> {
    let context = CliContext::resolve(&args.common)?;
    let result = load_member_show_result(&context.workspace_path()?, &args.member_handle)?;
    print_member_show(args.common.json.json, &result)
}
