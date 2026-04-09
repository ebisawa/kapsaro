// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::member::mutation::add_member;
use crate::cli::common::command::resolve_options;
use crate::cli::common::output::text::member::print_member_add_summary;
use crate::Error;

use super::AddArgs;

pub(crate) fn run(args: AddArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_id = add_member(&options, &args.filename, args.force)?;
    print_member_add_summary(&member_id);
    Ok(())
}
