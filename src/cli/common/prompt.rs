// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared interactive prompts for CLI commands.

use dialoguer::Confirm;
use secretenv_core::cli_api::presentation::tty;
use secretenv_core::{Error, Result};
#[cfg(test)]
use std::io::BufRead;

pub(crate) fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    if !tty::is_interactive() {
        return Err(Error::build_invalid_operation_error(
            "Interactive confirmation requires a terminal",
        ));
    }

    confirm_yes_no_interactive(prompt, default)
}

pub(crate) fn confirm_destructive_action(
    force: bool,
    prompt: &str,
    non_interactive_error: impl Into<String>,
    cancelled_error: impl Into<String>,
) -> Result<bool> {
    confirm_destructive_action_with(force, tty::is_interactive(), || {
        prompt_yes_no(prompt, false)
    })
    .map_err(|kind| match kind {
        DestructiveConfirmationError::NonInteractive => {
            Error::build_invalid_operation_error(non_interactive_error.into())
        }
        DestructiveConfirmationError::Cancelled => {
            Error::build_invalid_operation_error(cancelled_error.into())
        }
        DestructiveConfirmationError::Prompt(error) => error,
    })
}

pub(crate) fn confirm_destructive_action_or_cancel(
    force: bool,
    prompt: &str,
    non_interactive_error: impl Into<String>,
) -> Result<bool> {
    match confirm_destructive_action_with(force, tty::is_interactive(), || {
        prompt_yes_no(prompt, false)
    }) {
        Ok(accepted) => Ok(accepted),
        Err(DestructiveConfirmationError::Cancelled) => Ok(false),
        Err(DestructiveConfirmationError::NonInteractive) => Err(
            Error::build_invalid_operation_error(non_interactive_error.into()),
        ),
        Err(DestructiveConfirmationError::Prompt(error)) => Err(error),
    }
}

fn confirm_yes_no_interactive(prompt: &str, default: bool) -> Result<bool> {
    eprintln!();
    let answer = Confirm::new()
        .with_prompt(prompt)
        .default(default)
        .interact()
        .map_err(|e| Error::build_io_error_with_source("Failed to read user input", e.into()))?;
    eprintln!();
    Ok(answer)
}

enum DestructiveConfirmationError {
    NonInteractive,
    Cancelled,
    Prompt(Error),
}

fn confirm_destructive_action_with<Prompt>(
    force: bool,
    is_interactive: bool,
    prompt: Prompt,
) -> std::result::Result<bool, DestructiveConfirmationError>
where
    Prompt: FnOnce() -> Result<bool>,
{
    if force {
        return Ok(true);
    }
    if !is_interactive {
        return Err(DestructiveConfirmationError::NonInteractive);
    }
    match prompt().map_err(DestructiveConfirmationError::Prompt)? {
        true => Ok(true),
        false => Err(DestructiveConfirmationError::Cancelled),
    }
}

#[cfg(test)]
pub(crate) fn prompt_yes_no_with_reader<R>(
    prompt: &str,
    default: bool,
    mut reader: R,
) -> Result<bool>
where
    R: BufRead,
{
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{} {} ", prompt, suffix);

    let line = load_prompt_line(&mut reader)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }

    Ok(matches!(trimmed.to_ascii_lowercase().as_str(), "y" | "yes"))
}

#[cfg(test)]
pub(crate) fn confirm_destructive_action_with_reader<R>(
    force: bool,
    prompt: &str,
    non_interactive_error: impl Into<String>,
    cancelled_error: impl Into<String>,
    is_interactive: bool,
    mut reader: R,
) -> Result<bool>
where
    R: BufRead,
{
    confirm_destructive_action_with(force, is_interactive, || {
        prompt_yes_no_with_reader(prompt, false, &mut reader)
    })
    .map_err(|kind| match kind {
        DestructiveConfirmationError::NonInteractive => {
            Error::build_invalid_operation_error(non_interactive_error.into())
        }
        DestructiveConfirmationError::Cancelled => {
            Error::build_invalid_operation_error(cancelled_error.into())
        }
        DestructiveConfirmationError::Prompt(error) => error,
    })
}

#[cfg(test)]
fn load_prompt_line<R>(reader: &mut R) -> Result<String>
where
    R: BufRead,
{
    let mut bytes = Vec::new();

    loop {
        let buffer = reader
            .fill_buf()
            .map_err(|e| Error::build_io_error_with_source("Failed to read user input", e))?;
        if buffer.is_empty() {
            break;
        }

        let Some(terminator_index) = buffer.iter().position(|byte| matches!(byte, b'\n' | b'\r'))
        else {
            bytes.extend_from_slice(buffer);
            let len = buffer.len();
            reader.consume(len);
            continue;
        };

        bytes.extend_from_slice(&buffer[..terminator_index]);
        reader.consume(terminator_index + 1);
        break;
    }

    String::from_utf8(bytes)
        .map_err(|e| Error::build_parse_error_with_source("Failed to parse user input as UTF-8", e))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_prompt_test.rs"]
mod tests;
