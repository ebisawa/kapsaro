// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member handle and GitHub user resolution for commands.
//! Applies the CLI, environment and config precedence before prompting.

use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::member_handle::MemberHandleResolver;
use crate::error::MEMBER_HANDLE_REQUIRED_RECOVERY;
use crate::io::keystore::access::KeystoreAccess;
use crate::{Error, Result};

pub fn resolve_member_handle_input(
    member_handle: Option<String>,
    options: &CommonCommandOptions,
) -> Result<Option<String>> {
    let keystore = options
        .fixed_home()?
        .map(KeystoreAccess::open_optional_from_anchored_home)
        .transpose()?
        .flatten();
    MemberHandleResolver::fixed(options.global_config()?, keystore.as_ref())
        .resolve(member_handle)
        .map(|resolved| resolved.map(crate::model::identity::MemberHandle::into_string))
}

pub fn resolve_github_user_input(
    github_user: Option<String>,
    options: &CommonCommandOptions,
) -> Result<Option<String>> {
    crate::config::resolution::github_user::resolve_github_user_with_config(
        github_user,
        options.global_config()?,
    )
}

pub fn build_missing_member_handle_error(include_prompt_hint: bool) -> Error {
    let prompt_hint = if include_prompt_hint {
        "\n3. Run in an interactive terminal for prompt"
    } else {
        ""
    };

    Error::build_config_error(format!(
        "member handle not configured.\n\
         Reason: member handle is required but could not be determined.\n\
         Options:\n\
         1. Specify a member handle with --member-handle <handle>\n\
         2. Configure a default member handle explicitly{prompt_hint}"
    ))
    .with_recovery(MEMBER_HANDLE_REQUIRED_RECOVERY)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_identity_test.rs"]
mod tests;
