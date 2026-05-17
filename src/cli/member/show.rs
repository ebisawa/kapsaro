// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::member::print_member_show;
use secretenv_core::cli_api::app::member::query::load_member_show_result;
use secretenv_core::Error;

use super::ShowArgs;

pub(crate) fn run(args: ShowArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let result = load_member_show_result(&options, &args.member_handle)?;
    print_member_show(args.common.json.json, &result)
}
