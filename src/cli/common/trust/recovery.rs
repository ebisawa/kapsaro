// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store recovery for corrupted local trust cache files.
//!
//! Keeps reset planning, confirmation, and retry orchestration outside review prompts.

#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::output::text::print_warning;
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::trust::recovery::{
    build_trust_store_reset_plan, execute_trust_store_reset, requires_trust_store_reset,
    TrustStoreResetPlan,
};
use kapsaro_core::cli_api::presentation::path::format_path_relative_to_cwd;
use kapsaro_core::cli_api::presentation::tty;
use kapsaro_core::{Error, Result};

pub(crate) fn run_with_trust_store_reset_recovery<T, ResolveOwner, Run>(
    options: &CommonCommandOptions,
    resolve_owner_handle: ResolveOwner,
    mut run: Run,
) -> Result<T>
where
    ResolveOwner: Fn() -> Result<String>,
    Run: FnMut() -> Result<T>,
{
    let mut attempted_reset = false;
    loop {
        match run() {
            Ok(value) => return Ok(value),
            Err(error) if !attempted_reset && requires_trust_store_reset(&error) => {
                let owner_handle = resolve_owner_handle()?;
                recover_invalid_trust_store(options, &owner_handle, error)?;
                attempted_reset = true;
            }
            Err(error) => return Err(error),
        }
    }
}

fn recover_invalid_trust_store(
    options: &CommonCommandOptions,
    owner_handle: &str,
    error: Error,
) -> Result<()> {
    let plan = build_trust_store_reset_plan(options, owner_handle, error, tty::is_interactive())?;
    recover_prepared_trust_store(&plan, confirm_trust_store_reset)
}

fn recover_prepared_trust_store(
    plan: &TrustStoreResetPlan,
    confirm: impl FnOnce(&std::path::Path) -> Result<bool>,
) -> Result<()> {
    print_warning(&plan.warning_message);
    if !confirm(&plan.path)? {
        return Err(Error::build_invalid_operation_error(
            "Local trust store reset was declined".to_string(),
        ));
    }

    let outcome = execute_trust_store_reset(plan)?;
    eprintln!(
        "Deleted local trust store '{}'. Continuing with an empty trust cache.",
        format_path_relative_to_cwd(&outcome.path)
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn recover_invalid_trust_store_with_reader<R>(
    options: &CommonCommandOptions,
    owner_handle: &str,
    error: Error,
    reader: R,
    is_interactive: bool,
) -> Result<()>
where
    R: BufRead,
{
    let plan = build_trust_store_reset_plan(options, owner_handle, error, is_interactive)?;
    recover_prepared_trust_store(&plan, |path| {
        confirm_trust_store_reset_with_reader(path, reader)
    })
}

#[cfg(test)]
fn confirm_trust_store_reset_with_reader<R>(path: &std::path::Path, reader: R) -> Result<bool>
where
    R: BufRead,
{
    prompt_yes_no_with_reader(&trust_store_reset_prompt(path), false, reader)
}

fn confirm_trust_store_reset(path: &std::path::Path) -> Result<bool> {
    prompt_yes_no(&trust_store_reset_prompt(path), false)
}

fn trust_store_reset_prompt(path: &std::path::Path) -> String {
    format!(
        "Delete invalid local trust store '{}' and continue with an empty trust cache?",
        format_path_relative_to_cwd(path)
    )
}
