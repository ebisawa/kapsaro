// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove CLI handler.

use crate::app::trust::management::remove_known_key_command;
use crate::cli::common::command::{
    resolve_execution_input, resolve_options, resolve_trust_store_owner_member,
};
use crate::cli::common::output::text;
use crate::cli::common::output::text::trust::print_trust_remove_summary;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::Error;

use super::RemoveArgs;

pub(crate) fn run(args: RemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_id = args.member_handle.clone();
    let result = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_id.clone()),
        || {
            let (_, execution) = resolve_execution_input(&args.common, member_id.clone())?;
            remove_known_key_command(&options, &execution, &args.kid, options.verbose)
        },
    )?;
    text::print_warnings(&result.warnings);
    print_trust_remove_summary(&result.value.kid, &result.value.member_id);
    Ok(())
}
