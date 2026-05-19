// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signing helpers for unsigned kv-enc documents.

use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::signature::{sign_kv_document, SigningContext};
use crate::Result;

use super::document::KvDocumentDraft;

/// Serialize and sign an unsigned KV document.
pub(crate) fn sign_unsigned_kv_document(
    unsigned: KvDocumentDraft,
    master_key: &MasterKey,
    signing: &SigningContext<'_>,
) -> Result<String> {
    let token_codec = unsigned.token_codec();
    let content = unsigned.serialize_unsigned()?;
    sign_kv_document(
        &content,
        master_key,
        signing,
        token_codec,
        "sign_unsigned_kv_document",
    )
}

impl KvDocumentDraft {
    /// Serialize and sign the document.
    pub fn sign(self, master_key: &MasterKey, signing: &SigningContext<'_>) -> Result<String> {
        sign_unsigned_kv_document(self, master_key, signing)
    }
}
