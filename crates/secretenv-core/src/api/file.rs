// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! file-enc artifact facade.

use std::path::Path;

use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::encrypt::encrypt_file_content;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::verify::file::verify_file_content;
use crate::format::content::FileEncContent;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::support::fs::atomic::save_text;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::Result;

use super::key::{KeyContext, RecipientKeys};
use super::operation::OperationOptions;
use super::secret::SecretBytes;
use super::trust::RecipientSetSubject;

/// Parsed file-enc artifact.
#[derive(Debug, Clone)]
pub struct FileEncArtifact {
    content: FileEncContent,
}

/// Signature-verified file-enc artifact.
pub struct VerifiedFileEncArtifact {
    inner: VerifiedFileEncDocument,
}

impl FileEncArtifact {
    /// Parse file-enc JSON text after format detection.
    pub fn parse(content: impl Into<String>) -> Result<Self> {
        Ok(Self {
            content: FileEncContent::detect(content.into())?,
        })
    }

    /// Load file-enc JSON from a path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = load_text_with_limit(
            path.as_ref(),
            MAX_JSON_DOCUMENT_READ_SIZE,
            "file-enc artifact",
        )?;
        Self::parse(content)
    }

    /// Save the artifact text.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        save_text(path.as_ref(), self.as_str())
    }

    /// Encrypt bytes to a signed file-enc artifact.
    pub fn encrypt_bytes(
        plaintext: &[u8],
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<Self> {
        let debug = options.debug();
        let signing = build_signing_context(key_ctx.inner(), debug)?;
        let content =
            encrypt_file_content(plaintext, recipients.handles(), recipients.keys(), &signing)?;
        Self::parse(content)
    }

    /// Verify the artifact signature.
    pub fn verify(&self, options: OperationOptions) -> Result<VerifiedFileEncArtifact> {
        verify_file_content(&self.content, options.debug()).map(VerifiedFileEncArtifact::from_inner)
    }

    /// Return the serialized artifact text.
    pub fn as_str(&self) -> &str {
        self.content.as_str()
    }
}

impl VerifiedFileEncArtifact {
    pub(crate) fn from_inner(inner: VerifiedFileEncDocument) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(&self) -> &VerifiedFileEncDocument {
        &self.inner
    }

    /// Extract the recipient-set subject for trust policy evaluation.
    pub fn recipient_set_subject(&self) -> Result<RecipientSetSubject> {
        RecipientSetSubject::from_verified_file(self.inner())
    }

    /// Decrypt the verified artifact.
    pub fn decrypt_bytes(
        &self,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<SecretBytes> {
        decrypt_file_document_with_context(
            self.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
            options.debug(),
        )
        .map(|result| SecretBytes::from_zeroizing(result.value))
    }
}
