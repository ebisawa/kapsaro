// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::text::member::print_member_add_summary;
use kapsaro_core::cli_api::app::member::mutation::add_member;
use kapsaro_core::Error;

use super::AddArgs;

pub(crate) fn run(args: AddArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_handle = add_member(&options, &args.filename, args.force.force)?;
    print_member_add_summary(&member_handle);
    Ok(())
}
