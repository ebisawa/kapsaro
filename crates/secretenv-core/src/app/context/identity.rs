// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::{Error, Result};

pub fn resolve_member_handle_input(
    member_handle: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    crate::config::resolution::member_handle::resolve_member_handle_with_fallback(
        member_handle,
        base_dir,
    )
}

pub fn require_member_handle_input(
    member_handle: Option<String>,
    base_dir: Option<&Path>,
    include_prompt_hint: bool,
) -> Result<String> {
    resolve_member_handle_input(member_handle, base_dir)?
        .ok_or_else(|| build_missing_member_handle_error(include_prompt_hint))
}

pub fn resolve_github_user_input(
    github_user: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    crate::config::resolution::github_user::resolve_github_user(github_user, base_dir)
}

pub fn build_missing_member_handle_error(include_prompt_hint: bool) -> Error {
    let prompt_hint = if include_prompt_hint {
        "\n4. Run in an interactive terminal for prompt"
    } else {
        ""
    };

    Error::build_config_error(format!(
        "member handle not configured.\n\
         Reason: member handle is required but could not be determined.\n\
         Options:\n\
         1. Specify --member-handle <handle>\n\
         2. Set SECRETENV_MEMBER_HANDLE=<handle>\n\
         3. Run secretenv config set member_handle <handle>{prompt_hint}"
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_identity_test.rs"]
mod tests;
