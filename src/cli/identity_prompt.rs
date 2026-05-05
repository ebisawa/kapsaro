// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Interactive identity and registration prompts for CLI commands.

use dialoguer::{Input, Select};
use std::io::IsTerminal;
use std::path::Path;

use crate::app::context::identity::resolve_github_user_input;
use crate::app::context::ssh::SshKeyCandidateView;
use crate::cli::common::prompt::prompt_yes_no;
use crate::support::validation;
use crate::{Error, Result};

pub(crate) fn confirm_member_overwrite(member_handle: &str) -> Result<bool> {
    prompt_yes_no(
        &format!(
            "Member '{}' already exists in workspace. Update with current key?",
            member_handle
        ),
        false,
    )
}

/// Select a key from candidates.
/// 0 candidates → error (no Ed25519 key found)
/// 1 candidate  → automatic selection (return index 0)
/// n candidates → TTY: interactive dialoguer::Select / non-TTY: error
pub(crate) fn select_ssh_key(candidates: &[SshKeyCandidateView]) -> Result<usize> {
    if candidates.is_empty() {
        return Err(Error::Config {
            message: "No ssh-ed25519 key found in ssh-agent.\n\
                      Check available keys: ssh-add -L\n\
                      Ensure your SSH agent (e.g., 1Password) has an Ed25519 key available."
                .to_string(),
        });
    }

    if candidates.len() == 1 {
        return Ok(0);
    }

    if !is_prompt_available() {
        return Err(Error::Config {
            message: "Multiple Ed25519 keys found in ssh-agent.\n\
                      Specify which key to use with -i <path>, --ssh-identity <path>, or \
                      SECRETENV_SSH_IDENTITY environment variable."
                .to_string(),
        });
    }

    let items: Vec<String> = candidates.iter().map(format_candidate).collect();

    Select::new()
        .with_prompt("Multiple SSH keys found. Select one")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| Error::Config {
            message: format!("Failed to read selection: {e}"),
        })
}

/// Format a candidate for display in the interactive selector.
fn format_candidate(candidate: &SshKeyCandidateView) -> String {
    if candidate.comment.is_empty() {
        candidate.fingerprint.clone()
    } else {
        format!("{} ({})", candidate.fingerprint, candidate.comment)
    }
}

pub(crate) fn is_prompt_available() -> bool {
    std::io::stdin().is_terminal() && std::env::var("CI").is_err()
}

pub(crate) fn prompt_member_handle() -> Result<String> {
    Input::new()
        .with_prompt("Enter your member handle (alphanumeric and .@_+-)")
        .validate_with(|input: &String| {
            validation::validate_member_handle(input)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .interact_text()
        .map_err(|e| Error::Config {
            message: format!("Failed to read input: {}", e),
        })
}

pub(crate) fn prompt_github_user() -> Result<Option<String>> {
    let input: String = Input::new()
        .with_prompt("Enter your GitHub username (optional)")
        .allow_empty(true)
        .validate_with(|input: &String| {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                return Ok(());
            }
            validation::validate_github_login(trimmed)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .interact_text()
        .map_err(|e| Error::Config {
            message: format!("Failed to read input: {}", e),
        })?;

    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

pub(crate) fn resolve_key_generation_github_user(
    needs_new_key: bool,
    github_user: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    resolve_key_generation_github_user_with_prompt(
        needs_new_key,
        github_user,
        base_dir,
        is_prompt_available(),
        prompt_github_user,
    )
}

pub(crate) fn resolve_key_generation_github_user_with_prompt<F>(
    needs_new_key: bool,
    github_user: Option<String>,
    base_dir: Option<&Path>,
    prompt_available: bool,
    prompt: F,
) -> Result<Option<String>>
where
    F: FnOnce() -> Result<Option<String>>,
{
    if !needs_new_key {
        return Ok(None);
    }

    match resolve_github_user_input(github_user, base_dir)? {
        Some(github_user) => Ok(Some(github_user)),
        None if prompt_available => validate_prompt_github_user(prompt()?),
        None => Ok(None),
    }
}

fn validate_prompt_github_user(github_user: Option<String>) -> Result<Option<String>> {
    if let Some(login) = github_user.as_deref() {
        validation::validate_github_login(login)?;
    }
    Ok(github_user)
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_identity_prompt_test.rs"]
mod tests;
