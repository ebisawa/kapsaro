// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::member::mutation::remove_member;
use crate::cli::common::command::resolve_options;
use crate::cli::common::output::text::member::print_member_remove_summary;
use crate::Error;

use super::RemoveArgs;

pub(crate) fn run(args: RemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let result = remove_member(&options, &args.member_id, args.force)?;
    print_member_remove_summary(&result.member_id);

    Ok(())
}
