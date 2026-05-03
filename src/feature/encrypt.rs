// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Encrypt feature - file-enc encryption.

pub mod file;

use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::envelope::signature::SigningContext;
use crate::model::common::normalize_recipients;
use crate::model::public_key::VerifiedRecipientKey;
use crate::{Error, Result};

/// Validate that recipients count matches public keys count.
fn validate_recipient_key_count(
    recipients: &[String],
    members: &[VerifiedRecipientKey],
) -> Result<()> {
    if recipients.len() != members.len() {
        return Err(Error::InvalidArgument {
            message: format!(
                "Recipients count ({}) does not match public keys ({})",
                recipients.len(),
                members.len()
            ),
        });
    }
    Ok(())
}

/// Encrypt binary content to file-enc v4 format and return JSON string.
pub fn encrypt_file_content(
    content: &[u8],
    recipients: &[String],
    members: &[VerifiedRecipientKey],
    signing: &SigningContext<'_>,
) -> Result<String> {
    validate_recipient_key_count(recipients, members)?;

    let normalized_ids = normalize_recipients(recipients);
    let members_ordered: Vec<VerifiedRecipientKey> = normalized_ids
        .iter()
        .map(|id| {
            members
                .iter()
                .find(|m| m.document().protected.subject_handle == *id)
                .ok_or_else(|| Error::NotFound {
                    message: format!("Member not found for recipient: {}", id),
                })
                .cloned()
        })
        .collect::<Result<Vec<_>>>()?;

    let file_enc_doc = encrypt_file_document(content, &normalized_ids, &members_ordered, signing)?;

    serde_json::to_string_pretty(&file_enc_doc).map_err(|e| Error::Parse {
        message: format!("Failed to serialize FileEncDocument: {}", e),
        source: Some(Box::new(e)),
    })
}
