// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI-local formatting, validation, terminal, and process helpers.
//! Keeps presentation and process-boundary policy out of the core API.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use kapsaro_core::api::key::MemberHandle;
use kapsaro_core::{Error, Result};

const KID_LENGTH: usize = 32;
const DISPLAY_GROUP_SIZE: usize = 4;
const MAX_GITHUB_LOGIN_LENGTH: usize = 39;

pub(crate) fn format_path_relative_to_cwd(path: &Path) -> String {
    DisplayBase::resolve().relative(path)
}

struct DisplayBase {
    cwd: Option<PathBuf>,
}

impl DisplayBase {
    fn resolve() -> Self {
        Self {
            cwd: std::env::current_dir().ok(),
        }
    }

    fn relative(&self, path: &Path) -> String {
        if let Some(cwd) = &self.cwd {
            if let Ok(relative) = path.strip_prefix(cwd) {
                return non_empty_display(relative);
            }
        }
        path.display().to_string()
    }
}

fn non_empty_display(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        ".".to_string()
    } else {
        path.display().to_string()
    }
}

pub(crate) fn format_kid_display(kid: &str) -> Result<String> {
    let canonical = normalize_kid(kid)?;
    Ok(canonical
        .as_bytes()
        .chunks(DISPLAY_GROUP_SIZE)
        .map(|chunk| std::str::from_utf8(chunk).expect("canonical kid must stay ASCII"))
        .collect::<Vec<_>>()
        .join("-"))
}

pub(crate) fn format_kid_display_lossy(kid: &str) -> String {
    format_kid_display(kid).unwrap_or_else(|_| sanitize_display_field(kid))
}

fn normalize_kid(kid: &str) -> Result<String> {
    let canonical = kid
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if canonical.len() != KID_LENGTH || !canonical.iter().copied().all(is_kid_byte) {
        return Err(Error::build_invalid_argument_error(
            "kid must be 32 Crockford Base32 characters",
        ));
    }
    String::from_utf8(canonical)
        .map_err(|_| Error::build_invalid_argument_error("kid must be valid ASCII"))
}

fn is_kid_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z')
}

fn sanitize_display_field(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

pub(crate) fn validate_member_handle(value: &str) -> Result<()> {
    MemberHandle::try_from(value).map(|_| ())
}

pub(crate) fn validate_github_login(login: &str) -> Result<()> {
    if login.is_empty() || login.len() > MAX_GITHUB_LOGIN_LENGTH {
        return Err(Error::build_invalid_argument_error(
            "GitHub login must contain 1 to 39 characters",
        ));
    }
    let bytes = login.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(Error::build_invalid_argument_error(
            "GitHub login must start and end with alphanumeric",
        ));
    }
    if bytes.windows(2).any(|window| window == b"--")
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
    {
        return Err(Error::build_invalid_argument_error(
            "GitHub login must use alphanumeric characters and single hyphens",
        ));
    }
    Ok(())
}

pub(crate) mod tty {
    use std::io::IsTerminal;

    #[cfg(test)]
    use std::cell::Cell;

    #[cfg(test)]
    thread_local! {
        static INTERACTIVE_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    }

    pub(crate) fn is_interactive() -> bool {
        #[cfg(test)]
        if let Some(value) = INTERACTIVE_OVERRIDE.with(Cell::get) {
            return value;
        }
        std::io::stdin().is_terminal()
    }

    #[cfg(test)]
    pub(crate) fn set_interactive_override(value: Option<bool>) {
        INTERACTIVE_OVERRIDE.with(|cell| cell.set(value));
    }
}

pub(crate) fn remove_parent_kapsaro_env_vars(command: &mut Command) {
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_kapsaro_env_key(key))
    {
        command.env_remove(key);
    }
}

fn is_kapsaro_env_key(key: &OsStr) -> bool {
    key.to_str().is_some_and(|key| key.starts_with("KAPSARO_"))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_presentation_test.rs"]
mod tests;
