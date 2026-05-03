// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Validation utilities

use crate::{Error, Result};

/// Validate member_handle using the common ASCII identifier rules
///
/// Allows: alphanumeric (A-Z, a-z, 0-9) + special chars (.@_+-)
/// Must start with alphanumeric, max 254 chars
pub fn validate_member_handle(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(Error::InvalidArgument {
            message: "member_handle cannot be empty".to_string(),
        });
    }
    if id.len() > 254 {
        return Err(Error::InvalidArgument {
            message: format!("member_handle too long: {} chars (max 254)", id.len()),
        });
    }

    let first = id.chars().next().ok_or_else(|| Error::InvalidArgument {
        message: "member_handle cannot be empty".to_string(),
    })?;
    if !first.is_ascii_alphanumeric() {
        return Err(Error::InvalidArgument {
            message: format!("member_handle must start with alphanumeric: '{}'", id),
        });
    }

    if let Some(c) = id
        .chars()
        .find(|&c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '@' | '_' | '+' | '-'))
    {
        return Err(Error::InvalidArgument {
            message: format!(
                "invalid character '{}' in member_handle (only [A-Za-z0-9.@_+-])",
                c
            ),
        });
    }

    Ok(())
}

/// Validate a GitHub login.
///
/// GitHub logins are ASCII identifiers for REST `/users/{login}` lookups.
pub fn validate_github_login(login: &str) -> Result<()> {
    if login.is_empty() {
        return Err(Error::InvalidArgument {
            message: "GitHub login cannot be empty".to_string(),
        });
    }
    if login.len() > 39 {
        return Err(Error::InvalidArgument {
            message: format!("GitHub login too long: {} chars (max 39)", login.len()),
        });
    }

    let bytes = login.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(Error::InvalidArgument {
            message: format!("GitHub login must start with alphanumeric: '{}'", login),
        });
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(Error::InvalidArgument {
            message: format!("GitHub login must end with alphanumeric: '{}'", login),
        });
    }

    let mut previous_hyphen = false;
    for &byte in bytes {
        if byte == b'-' {
            if previous_hyphen {
                return Err(Error::InvalidArgument {
                    message: format!(
                        "GitHub login must not contain consecutive hyphens: '{}'",
                        login
                    ),
                });
            }
            previous_hyphen = true;
            continue;
        }
        if !byte.is_ascii_alphanumeric() {
            return Err(Error::InvalidArgument {
                message: format!(
                    "invalid character '{}' in GitHub login (only [A-Za-z0-9-])",
                    byte as char
                ),
            });
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
    if name.is_empty() {
        return Err(Error::InvalidArgument {
            message: "name cannot be empty".to_string(),
        });
    }

    if name.starts_with('.') {
        return Err(Error::InvalidArgument {
            message: format!("name must not start with '.': '{}'", name),
        });
    }

    if name == ".." {
        return Err(Error::InvalidArgument {
            message: "name must not be '..'".to_string(),
        });
    }

    if let Some(c) = name
        .bytes()
        .find(|&b| b == b'/' || b == b'\\' || b == 0 || !(0x20..=0x7E).contains(&b))
    {
        return Err(Error::InvalidArgument {
            message: format!(
                "invalid byte 0x{:02x} in name (only printable ASCII without '/' or '\\\\')",
                c
            ),
        });
    }

    Ok(())
}
