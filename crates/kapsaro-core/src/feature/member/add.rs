// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member add feature - validate incoming PublicKey content.

use super::verification::verify_member_public_key_file;
use crate::format::schema::document::parse_public_key_str;
use crate::model::public_key::PublicKey;
use crate::Result;

#[derive(Debug, Clone)]
pub struct MemberAddition {
    pub member_handle: String,
    pub public_key: PublicKey,
}

pub fn build_member_addition_from_content(
    content: &str,
    source_name: &str,
    debug: bool,
) -> Result<MemberAddition> {
    let public_key = parse_public_key_str(content, source_name)?;
    let verified = verify_member_public_key_file(
        &public_key,
        Some(&public_key.protected.subject_handle),
        source_name,
        debug,
    )?;

    Ok(MemberAddition {
        member_handle: verified.member_handle,
        public_key,
    })
}
