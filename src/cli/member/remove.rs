// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use std::io::BufRead;

use crate::app::member::mutation::{preview_member_removal, remove_member};
use crate::cli::common::command::resolve_options;
use crate::cli::common::output::text::member::print_member_remove_summary;
use crate::cli::common::output::text::{print_warning, print_warning_line};
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use crate::support::path::display_path_relative_to_cwd;
use crate::support::tty;
use crate::Error;

use super::RemoveArgs;

pub(crate) fn run(args: RemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let preview = preview_member_removal(&options, &args.member_id)?;
    print_member_remove_preview(&preview);
    confirm_member_remove(args.force, &args.member_id)?;
    let result = remove_member(&options, &args.member_id)?;
    print_member_remove_summary(&result.member_id);

    Ok(())
}

fn print_member_remove_preview(preview: &crate::app::member::types::MemberRemovePreview) {
    for warning in &preview.warnings {
        print_warning(warning);
    }

    if preview.affected_artifacts.is_empty() {
        return;
    }

    print_warning_line(&format!(
        "Warning: removing member '{}' affects {} encrypted artifact(s):",
        preview.member_id,
        preview.affected_artifacts.len()
    ));
    for artifact in &preview.affected_artifacts {
        eprintln!("  {}", display_path_relative_to_cwd(artifact));
    }
    print_warning_line(
        "Run `secretenv rewrap` after removal to update recipients in encrypted artifacts.",
    );
}

fn confirm_member_remove(force: bool, member_id: &str) -> Result<(), Error> {
    if force {
        return Ok(());
    }
    if !tty::is_interactive() {
        return Err(Error::invalid_operation(format!(
            "Refusing to remove member '{}' without --force in non-interactive mode",
            member_id
        )));
    }

    if prompt_yes_no(
        &format!("Remove member '{}' from the workspace?", member_id),
        false,
    )? {
        return Ok(());
    }

    Err(Error::invalid_operation(format!(
        "Member removal cancelled for '{}'",
        member_id
    )))
}

#[cfg(test)]
fn confirm_member_remove_with_reader<R>(
    force: bool,
    member_id: &str,
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
        return Err(Error::invalid_operation(format!(
            "Refusing to remove member '{}' without --force in non-interactive mode",
            member_id
        )));
    }

    if prompt_yes_no_with_reader(
        &format!("Remove member '{}' from the workspace?", member_id),
        false,
        &mut reader,
    )? {
        return Ok(());
    }

    Err(Error::invalid_operation(format!(
        "Member removal cancelled for '{}'",
        member_id
    )))
}

#[cfg(test)]
#[path = "../../../tests/unit/cli_member_remove_test.rs"]
mod tests;
