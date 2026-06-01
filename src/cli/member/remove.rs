// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::command::resolve_options_with_allow_expired_key;
use crate::cli::common::output::text::member::print_member_remove_summary;
use crate::cli::common::output::text::{print_warning, print_warning_line};
use crate::cli::common::prompt::confirm_destructive_action;
#[cfg(test)]
use crate::cli::common::prompt::confirm_destructive_action_with_reader;
use kapsaro_core::cli_api::app::member::mutation::{evaluate_member_removal, remove_member};
use kapsaro_core::cli_api::presentation::path::format_path_relative_to_cwd;
use kapsaro_core::Error;

use super::RemoveArgs;

pub(crate) fn run(args: RemoveArgs) -> Result<(), Error> {
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let preview = evaluate_member_removal(&options, &args.member_handle)?;
    print_member_remove_preview(&preview);
    confirm_member_remove(args.force.force, &args.member_handle)?;
    let result = remove_member(&options, &args.member_handle)?;
    print_member_remove_summary(&result.member_handle);

    Ok(())
}

fn print_member_remove_preview(
    preview: &kapsaro_core::cli_api::app::member::types::MemberRemovalReport,
) {
    for warning in &preview.warnings {
        print_warning(warning);
    }

    if preview.affected_artifacts.is_empty() {
        return;
    }

    print_warning_line(&format!(
        "Warning: removing member '{}' affects {} encrypted artifact(s):",
        preview.member_handle,
        preview.affected_artifacts.len()
    ));
    for artifact in &preview.affected_artifacts {
        eprintln!("  {}", format_path_relative_to_cwd(artifact));
    }
    print_warning_line(
        "Run `kapsaro rewrap` after removal to update recipients in encrypted artifacts.",
    );
}

fn confirm_member_remove(force: bool, member_handle: &str) -> Result<(), Error> {
    confirm_destructive_action(
        force,
        &member_remove_prompt(member_handle),
        member_remove_non_interactive_error(member_handle),
        member_remove_cancelled_error(member_handle),
    )?;
    Ok(())
}

#[cfg(test)]
fn confirm_member_remove_with_reader<R>(
    force: bool,
    member_handle: &str,
    is_interactive: bool,
    mut reader: R,
) -> Result<(), Error>
where
    R: BufRead,
{
    confirm_destructive_action_with_reader(
        force,
        &member_remove_prompt(member_handle),
        member_remove_non_interactive_error(member_handle),
        member_remove_cancelled_error(member_handle),
        is_interactive,
        &mut reader,
    )?;
    Ok(())
}

fn member_remove_prompt(member_handle: &str) -> String {
    format!("Remove member '{}' from the workspace?", member_handle)
}

fn member_remove_non_interactive_error(member_handle: &str) -> String {
    format!(
        "Member removal requires --force.\n\
         Member: {}\n\
         Reason: non-interactive mode.",
        member_handle
    )
}

fn member_remove_cancelled_error(member_handle: &str) -> String {
    format!("Member removal cancelled for '{}'", member_handle)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_member_remove_test.rs"]
mod tests;
