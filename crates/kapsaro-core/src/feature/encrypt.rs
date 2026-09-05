// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Encrypt feature - file-enc encryption.

pub mod file;

use crate::feature::context::crypto::SigningContext;
use crate::feature::encrypt::file::encrypt_file_document;
use crate::model::public_key::VerifiedRecipientKey;
use crate::{Error, Result};

/// Encrypt binary content to file-enc v5 format and return JSON string.
///
/// The recipient set is the handle of every member given, so a member without
/// a matching recipient entry or a recipient without a key cannot occur.
pub fn encrypt_file_content(
    content: &[u8],
    members: &[VerifiedRecipientKey],
    signing: &SigningContext<'_>,
) -> Result<String> {
    let mut members_ordered = members.to_vec();
    members_ordered.sort_by(|a, b| {
        a.document()
            .protected
            .subject_handle
            .cmp(&b.document().protected.subject_handle)
    });
    members_ordered.dedup_by(|a, b| {
        a.document().protected.subject_handle == b.document().protected.subject_handle
    });
    let recipient_ids: Vec<String> = members_ordered
        .iter()
        .map(|member| member.document().protected.subject_handle.clone())
        .collect();

    let file_enc_doc = encrypt_file_document(content, &recipient_ids, &members_ordered, signing)?;

    serde_json::to_string_pretty(&file_enc_doc).map_err(|e| {
        Error::build_parse_error_with_source(
            format!("Failed to serialize FileEncDocument: {}", e),
            e,
        )
    })
}

#[cfg(test)]
#[path = "../../tests/unit/internal/feature_encrypt_test.rs"]
mod feature_encrypt_test;
