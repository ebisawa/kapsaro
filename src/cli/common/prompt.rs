// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared interactive prompts for CLI commands.

use crate::{Error, Result};
use std::io::BufRead;

pub(crate) fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    prompt_yes_no_with_reader(prompt, default, std::io::stdin().lock())
}

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

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| Error::io_with_source("Failed to read user input", e))?;

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }

    Ok(matches!(trimmed.to_ascii_lowercase().as_str(), "y" | "yes"))
}

#[cfg(test)]
#[path = "../../../tests/unit/cli_common_prompt_test.rs"]
mod tests;
