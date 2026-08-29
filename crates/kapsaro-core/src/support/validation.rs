// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Validation utilities

use crate::support::limits::{MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH, MAX_MEMBER_HANDLE_LENGTH};
use crate::{Error, Result};

/// Length of the `.kvenc` suffix appended to a validated basename.
/// Spelled out here because this layer cannot reach the format layer, which
/// holds the extension itself and asserts the same length at compile time.
const KV_ENC_EXTENSION_LENGTH: usize = 6;

/// Longest login GitHub issues.
const MAX_GITHUB_LOGIN_LENGTH: usize = 39;

/// Validate member_handle using the common ASCII identifier rules
///
/// Allows: alphanumeric (A-Z, a-z, 0-9) + special chars (.@_+-)
/// Must start with alphanumeric
pub fn validate_member_handle(id: &str) -> Result<()> {
    ensure_member_handle_length(id)?;
    ensure_member_handle_starts_alphanumeric(id)?;
    ensure_member_handle_characters(id)
}

fn ensure_member_handle_length(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(Error::build_invalid_argument_error(
            "member_handle cannot be empty".to_string(),
        ));
    }
    if id.len() > MAX_MEMBER_HANDLE_LENGTH {
        return Err(Error::build_invalid_argument_error(format!(
            "member_handle too long: {} chars (max {})",
            id.len(),
            MAX_MEMBER_HANDLE_LENGTH
        )));
    }
    Ok(())
}

fn ensure_member_handle_starts_alphanumeric(id: &str) -> Result<()> {
    match id.chars().next() {
        Some(first) if first.is_ascii_alphanumeric() => Ok(()),
        Some(_) => Err(Error::build_invalid_argument_error(format!(
            "member_handle must start with alphanumeric: '{}'",
            id
        ))),
        None => Err(Error::build_invalid_argument_error(
            "member_handle cannot be empty".to_string(),
        )),
    }
}

fn ensure_member_handle_characters(id: &str) -> Result<()> {
    match id
        .chars()
        .find(|&c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '@' | '_' | '+' | '-'))
    {
        Some(c) => Err(Error::build_invalid_argument_error(format!(
            "invalid character '{}' in member_handle (only [A-Za-z0-9.@_+-])",
            c
        ))),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_validation_test.rs"]
mod support_validation_test;

/// Validate a GitHub login.
///
/// GitHub logins are ASCII identifiers for REST `/users/{login}` lookups.
pub fn validate_github_login(login: &str) -> Result<()> {
    ensure_github_login_length(login)?;
    ensure_github_login_boundaries(login)?;
    ensure_github_login_characters(login)
}

fn ensure_github_login_length(login: &str) -> Result<()> {
    if login.is_empty() {
        return Err(Error::build_invalid_argument_error(
            "GitHub login cannot be empty".to_string(),
        ));
    }
    if login.len() > MAX_GITHUB_LOGIN_LENGTH {
        return Err(Error::build_invalid_argument_error(format!(
            "GitHub login too long: {} chars (max {})",
            login.len(),
            MAX_GITHUB_LOGIN_LENGTH
        )));
    }
    Ok(())
}

fn ensure_github_login_boundaries(login: &str) -> Result<()> {
    // The length rule rejects an empty login before this rule indexes the bytes.
    let bytes = login.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(Error::build_invalid_argument_error(format!(
            "GitHub login must start with alphanumeric: '{}'",
            login
        )));
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(Error::build_invalid_argument_error(format!(
            "GitHub login must end with alphanumeric: '{}'",
            login
        )));
    }
    Ok(())
}

fn ensure_github_login_characters(login: &str) -> Result<()> {
    let mut previous_hyphen = false;
    for &byte in login.as_bytes() {
        if byte == b'-' {
            if previous_hyphen {
                return Err(Error::build_invalid_argument_error(format!(
                    "GitHub login must not contain consecutive hyphens: '{}'",
                    login
                )));
            }
            previous_hyphen = true;
            continue;
        }
        if !byte.is_ascii_alphanumeric() {
            return Err(Error::build_invalid_argument_error(format!(
                "invalid character '{}' in GitHub login (only [A-Za-z0-9-])",
                byte as char
            )));
        }
        previous_hyphen = false;
    }
    Ok(())
}

/// Validate a KV file basename supplied via `-n/--name`.
///
/// The name is interpolated into `<workspace>/secrets/<name>.kvenc`, so it must
/// be a safe basename. Rejects anything that could escape the secrets directory
/// or resolve to a non-obvious path.
pub fn validate_kv_file_basename(name: &str) -> Result<()> {
    ensure_kv_basename_is_a_plain_name(name)?;
    ensure_kv_basename_bytes(name)?;
    ensure_kv_basename_length(name)
}

/// Reject names that address something other than a file inside the secrets
/// directory, including `.`, `..`, and hidden names.
fn ensure_kv_basename_is_a_plain_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::build_invalid_argument_error(
            "name cannot be empty".to_string(),
        ));
    }
    if name.starts_with('.') {
        return Err(Error::build_invalid_argument_error(format!(
            "name must not start with '.': '{}'",
            name
        )));
    }
    Ok(())
}

fn ensure_kv_basename_bytes(name: &str) -> Result<()> {
    match name
        .bytes()
        .find(|&b| b == b'/' || b == b'\\' || b == 0 || !(0x20..=0x7E).contains(&b))
    {
        Some(c) => Err(Error::build_invalid_argument_error(format!(
            "invalid byte 0x{:02x} in name (only printable ASCII without '/' or '\\\\')",
            c
        ))),
        None => Ok(()),
    }
}

fn ensure_kv_basename_length(name: &str) -> Result<()> {
    let max_name = MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH.saturating_sub(KV_ENC_EXTENSION_LENGTH);
    if name.len() > max_name {
        return Err(Error::build_invalid_argument_error(format!(
            "name too long: {} chars (max {})",
            name.len(),
            max_name
        )));
    }
    Ok(())
}
