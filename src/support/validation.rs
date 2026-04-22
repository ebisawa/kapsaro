// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Validation utilities

use crate::{Error, Result};

/// Validate member_id using the common ASCII identifier rules
///
/// Allows: alphanumeric (A-Z, a-z, 0-9) + special chars (.@_+-)
/// Must start with alphanumeric, max 254 chars
pub fn validate_member_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(Error::InvalidArgument {
            message: "member_id cannot be empty".to_string(),
        });
    }
    if id.len() > 254 {
        return Err(Error::InvalidArgument {
            message: format!("member_id too long: {} chars (max 254)", id.len()),
        });
    }

    let first = id.chars().next().ok_or_else(|| Error::InvalidArgument {
        message: "member_id cannot be empty".to_string(),
    })?;
    if !first.is_ascii_alphanumeric() {
        return Err(Error::InvalidArgument {
            message: format!("member_id must start with alphanumeric: '{}'", id),
        });
    }

    if let Some(c) = id
        .chars()
        .find(|&c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '@' | '_' | '+' | '-'))
    {
        return Err(Error::InvalidArgument {
            message: format!(
                "invalid character '{}' in member_id (only [A-Za-z0-9.@_+-])",
                c
            ),
        });
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
