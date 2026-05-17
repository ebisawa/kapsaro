// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::text::member::print_member_remove_summary;
use crate::cli::common::output::text::{print_warning, print_warning_line};
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use secretenv_core::cli_api::app::member::mutation::{evaluate_member_removal, remove_member};
use secretenv_core::cli_api::presentation::path::format_path_relative_to_cwd;
use secretenv_core::cli_api::presentation::tty;
use secretenv_core::Error;

use super::RemoveArgs;

pub(crate) fn run(args: RemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let preview = evaluate_member_removal(&options, &args.member_handle)?;
    print_member_remove_preview(&preview);
    confirm_member_remove(args.force.force, &args.member_handle)?;
    let result = remove_member(&options, &args.member_handle)?;
    print_member_remove_summary(&result.member_handle);

    Ok(())
}

fn print_member_remove_preview(
    preview: &secretenv_core::cli_api::app::member::types::MemberRemovalReport,
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
        "Run `secretenv rewrap` after removal to update recipients in encrypted artifacts.",
    );
}

fn confirm_member_remove(force: bool, member_handle: &str) -> Result<(), Error> {
    if force {
        return Ok(());
    }
    if !tty::is_interactive() {
        return Err(Error::build_invalid_operation_error(format!(
            "Refusing to remove member '{}' without --force in non-interactive mode",
            member_handle
        )));
    }

    if prompt_yes_no(
        &format!("Remove member '{}' from the workspace?", member_handle),
        false,
    )? {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(format!(
        "Member removal cancelled for '{}'",
        member_handle
    )))
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
    if force {
        return Ok(());
    }
    if !is_interactive {
        return Err(Error::build_invalid_operation_error(format!(
            "Refusing to remove member '{}' without --force in non-interactive mode",
            member_handle
        )));
    }

    if prompt_yes_no_with_reader(
        &format!("Remove member '{}' from the workspace?", member_handle),
        false,
        &mut reader,
    )? {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(format!(
        "Member removal cancelled for '{}'",
        member_handle
    )))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_member_remove_test.rs"]
mod tests;
