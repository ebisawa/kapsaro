// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::config::resolution::github_user::resolve_github_user;
use crate::config::resolution::member_id::resolve_member_id_with_fallback;
use crate::{Error, Result};

pub(crate) fn resolve_member_id_input(
    member_id: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    resolve_member_id_with_fallback(member_id, base_dir)
}

pub(crate) fn require_member_id_input(
    member_id: Option<String>,
    base_dir: Option<&Path>,
    include_prompt_hint: bool,
) -> Result<String> {
    resolve_member_id_input(member_id, base_dir)?
        .ok_or_else(|| build_missing_member_id_error(include_prompt_hint))
}

pub(crate) fn resolve_github_user_input(
    github_user: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    resolve_github_user(github_user, base_dir)
}

pub(crate) fn build_missing_member_id_error(include_prompt_hint: bool) -> Error {
    let prompt_hint = if include_prompt_hint {
        "\n                  4. Run in an interactive terminal for prompt"
    } else {
        ""
    };

    Error::Config {
        message: format!(
            "member_id not configured.\n\
             member_id is required but could not be determined.\n\
             Options:\n\
             1. Specify --member-id <id>\n\
             2. Set environment variable: export SECRETENV_MEMBER_ID=<id>\n\
             3. Set in config: secretenv config set member_id <id>{prompt_hint}"
        ),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/app_context_identity_test.rs"]
mod tests;
