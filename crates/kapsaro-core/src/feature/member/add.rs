// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member add feature - validate incoming PublicKey content.

use super::verification::verify_member_public_key_file;
use crate::format::schema::document::parse_public_key_str;
use crate::Result;

/// Validate the incoming PublicKey content and return the member handle it belongs to.
pub fn build_member_addition_from_content(content: &str, source_name: &str) -> Result<String> {
    let public_key = parse_public_key_str(content, source_name)?;
    let verified = verify_member_public_key_file(
        &public_key,
        Some(&public_key.protected.subject_handle),
        source_name,
    )?;

    Ok(verified.member_handle)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_member_add_test.rs"]
mod feature_member_add_test;
