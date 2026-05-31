// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient-set evidence extraction from encrypted artifacts.
//! Converts file and KV wire documents into approval-review inputs.

use crate::format::content::{EncContent, FileEncContent, KvEncContent};
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::document::KvEncDocument;
use crate::Result;

use super::record::ArtifactRecipientSet;

pub struct ArtifactRecipientEvidence {
    pub recipient_set: ArtifactRecipientSet,
    pub recipient_handles: Vec<String>,
}

pub(crate) fn file_recipient_evidence(
    document: &FileEncDocument,
) -> Result<ArtifactRecipientEvidence> {
    Ok(ArtifactRecipientEvidence {
        recipient_set: ArtifactRecipientSet::from_wrap_items(
            document.protected.sid,
            &document.protected.wrap,
        )?,
        recipient_handles: document.protected.recipients(),
    })
}

pub(crate) fn kv_recipient_evidence(document: &KvEncDocument) -> Result<ArtifactRecipientEvidence> {
    Ok(ArtifactRecipientEvidence {
        recipient_set: ArtifactRecipientSet::from_wrap_items(
            document.head.sid,
            &document.wrap.wrap,
        )?,
        recipient_handles: document
            .wrap
            .wrap
            .iter()
            .map(|item| item.recipient_handle.clone())
            .collect(),
    })
}

pub(crate) fn file_content_recipient_evidence(
    content: &FileEncContent,
) -> Result<ArtifactRecipientEvidence> {
    file_recipient_evidence(&content.parse()?)
}

pub(crate) fn kv_content_recipient_evidence(
    content: &KvEncContent,
) -> Result<ArtifactRecipientEvidence> {
    kv_recipient_evidence(&content.parse()?)
}

pub(crate) fn encrypted_content_recipient_evidence(
    content: &EncContent,
) -> Result<ArtifactRecipientEvidence> {
    match content {
        EncContent::FileEnc(file_content) => file_content_recipient_evidence(file_content),
        EncContent::KvEnc(kv_content) => kv_content_recipient_evidence(kv_content),
    }
}
