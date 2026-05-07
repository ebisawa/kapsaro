// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust list CLI handler.

use crate::app::context::member::resolve_required_member;
use crate::app::trust::list::{list_known_keys, list_recipient_sets};
use crate::cli::common::command::resolve_options;
use crate::cli::common::output::trust::{print_recipient_set_list, print_trust_list};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::Error;

use super::ListArgs;

pub(crate) fn run_keys(args: ListArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_handle = resolve_required_member(&options, args.member_handle.clone())?;
    let result = run_with_trust_store_reset_recovery(
        &options,
        || Ok(member_handle.clone()),
        || list_known_keys(&options, &member_handle),
    )?;
    print_trust_list(args.common.json, &result)
}

pub(crate) fn run_recipients(args: ListArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_handle = resolve_required_member(&options, args.member_handle.clone())?;
    let result = run_with_trust_store_reset_recovery(
        &options,
        || Ok(member_handle.clone()),
        || list_recipient_sets(&options, &member_handle),
    )?;
    print_recipient_set_list(args.common.json, &result)
}
