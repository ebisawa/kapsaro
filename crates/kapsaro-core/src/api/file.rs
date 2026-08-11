// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! file-enc artifact facade.

use sha2::{Digest, Sha256};
use std::io::Read;

use crate::api::artifact_text::{ArtifactLoadPolicy, ArtifactText};
use crate::feature::context::crypto::build_signing_context;
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::encrypt::encrypt_file_content;
use crate::feature::envelope::key_possession::verify_file_key_possession;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context;
use crate::feature::verify::file::verify_file_content_for_operation;
use crate::format::content::FileEncContent;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
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

/// Trust-authorized file-enc artifact bound to its decryption key.
pub struct TrustedFileEncArtifact<'a> {
    artifact: &'a VerifiedFileEncArtifact,
    key_ctx: &'a KeyContext,
}

/// Authorized file read operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReadOperation {
    Decrypt,
}

const FILE_ENC_LOAD_POLICY: ArtifactLoadPolicy =
    ArtifactLoadPolicy::new(MAX_JSON_DOCUMENT_READ_SIZE, "file-enc artifact");

impl FileEncArtifact {
    /// Parse file-enc JSON text after format detection.
    pub fn parse(content: impl Into<String>) -> Result<Self> {
        ArtifactText::parse(content, FILE_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Load file-enc JSON from a path.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ArtifactText::load(path, FILE_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Load file-enc JSON from a bounded UTF-8 reader.
    pub fn load_reader(reader: impl Read, source_name: impl Into<String>) -> Result<Self> {
        ArtifactText::load_reader(reader, source_name, FILE_ENC_LOAD_POLICY).map(Self::from_text)
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
    ) -> Result<Self> {
        let signing = build_signing_context(key_ctx.inner())?;
        let content =
            encrypt_file_content(plaintext, recipients.handles(), recipients.keys(), &signing)?;
        Self::parse(content)
    }

    /// Verify the artifact signature.
    pub fn verify(&self, options: OperationOptions) -> Result<VerifiedFileEncArtifact> {
        verify_file_content_for_operation(self.text.content(), options.allow_expired_key())
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

    pub(crate) fn binding_digest(&self) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(self.inner.document()).map_err(|error| {
            crate::Error::build_parse_error_with_source(
                "Failed to serialize verified file artifact binding".to_string(),
                error,
            )
        })?;
        Ok(Sha256::digest(bytes).into())
    }

    /// Extract the recipient-set subject for trust policy evaluation.
    pub fn recipient_set_subject(&self) -> Result<RecipientSetSubject> {
        RecipientSetSubject::from_verified_file(self.inner())
    }
}

impl<'a> TrustedFileEncArtifact<'a> {
    pub(crate) fn from_authorized(
        artifact: &'a VerifiedFileEncArtifact,
        key_ctx: &'a KeyContext,
        options: OperationOptions,
    ) -> Result<Self> {
        key_ctx.enforce_decryption_key_not_expired(
            &artifact.inner().document().protected.wrap,
            options,
        )?;
        let master_key = unwrap_master_key_for_file_with_context(
            artifact.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
        )?;
        verify_file_key_possession(artifact.inner(), master_key.value)?;
        Ok(Self { artifact, key_ctx })
    }

    /// Decrypt the trust-authorized artifact.
    pub fn decrypt_bytes(&self) -> Result<SecretBytes> {
        decrypt_file_document_with_context(
            self.artifact.inner(),
            self.key_ctx.member_handle(),
            self.key_ctx.inner(),
        )
        .map(|result| SecretBytes::from_zeroizing(result.value))
    }
}
