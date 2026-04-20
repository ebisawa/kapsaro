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
