// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! file-enc artifact facade.

use crate::api::artifact_text::ArtifactText;
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::encrypt::encrypt_file_content;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::verify::file::verify_file_content_for_operation;
use crate::format::content::FileEncContent;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::Result;

use super::key::{KeyContext, RecipientKeys};
use super::operation::OperationOptions;
use super::secret::SecretBytes;
use super::trust::RecipientSetSubject;

/// Parsed file-enc artifact.
#[derive(Debug, Clone)]
pub struct FileEncArtifact {
    text: ArtifactText<FileEncContent>,
}

/// Signature-verified file-enc artifact.
pub struct VerifiedFileEncArtifact {
    inner: VerifiedFileEncDocument,
}

impl FileEncArtifact {
    /// Parse file-enc JSON text after format detection.
    pub fn parse(content: impl Into<String>) -> Result<Self> {
        ArtifactText::parse(content).map(Self::from_text)
    }

    /// Load file-enc JSON from a path.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ArtifactText::load(path, "file-enc artifact").map(Self::from_text)
    }

    /// Save the artifact text.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        self.text.save(path)
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
        verify_file_content_for_operation(
            self.text.content(),
            options.debug(),
            options.allow_expired_key(),
        )
        .map(VerifiedFileEncArtifact::from_inner)
    }

    /// Return the serialized artifact text.
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }

    fn from_text(text: ArtifactText<FileEncContent>) -> Self {
        Self { text }
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
        key_ctx
            .enforce_decryption_key_not_expired(&self.inner().document.protected.wrap, options)?;
        decrypt_file_document_with_context(
            self.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
            options.debug(),
        )
        .map(|result| SecretBytes::from_zeroizing(result.value))
    }
}
