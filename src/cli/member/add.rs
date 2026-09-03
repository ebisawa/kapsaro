// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI entry point for `member add`.
//! Adds a member from a public key file and prints a summary of the added handle.

use crate::cli::common::context::CliContext;
use crate::cli::common::output::text::member::print_member_add_summary;
use kapsaro_core::api::member::mutation::add_member;
use kapsaro_core::Error;

use super::AddArgs;

pub(crate) fn run(args: AddArgs) -> Result<(), Error> {
    let context = CliContext::resolve(&args.common)?;
    let member_handle = add_member(&context.workspace_path()?, &args.filename, args.force.force)?;
    print_member_add_summary(&member_handle);
    Ok(())
}
