// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Standard file-enc artifact operations and capability types.

use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::io::Read;

use crate::feature::context::crypto::{build_signing_context, DecryptionKeyInfo};
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::encrypt::encrypt_file_content;
use crate::feature::envelope::key_possession::verify_file_key_possession;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context;
use crate::feature::verify::file::verify_file_content_for_operation;
use crate::format::content::FileEncContent;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::verification::SignatureVerificationProof;
use crate::service::artifact_text::{ArtifactLoadPolicy, ArtifactText};
use crate::support::fs::atomic::{save_bytes_restricted, save_text};
use crate::support::fs::load_bytes;
use crate::support::fs::relative::{load_text_with_limit_at, DirectoryFd};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::support::warning::push_unique_warning;
use crate::Result;

use crate::service::key::{KeyContext, RecipientKeys};
use crate::service::operation::OperationOptions;
use crate::service::secret::SecretBytes;
use crate::service::trust::{push_signature_verification_warnings, RecipientSetSubject};

/// Parsed file-enc artifact.
#[derive(Debug, Clone)]
pub struct FileEncArtifact {
    text: ArtifactText<FileEncContent>,
}

/// Signature-verified file-enc artifact.
#[derive(Clone)]
pub struct VerifiedFileEncArtifact {
    content: FileEncContent,
    inner: VerifiedFileEncDocument,
}

/// Trust-authorized file-enc artifact bound to its decryption key.
pub struct TrustedFileEncArtifact<'a> {
    artifact: Cow<'a, VerifiedFileEncArtifact>,
    key_ctx: &'a KeyContext,
    warnings: Vec<String>,
}

/// Authorized file read operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReadOperation {
    Decrypt,
}

const FILE_ENC_LOAD_POLICY: ArtifactLoadPolicy =
    ArtifactLoadPolicy::new(MAX_JSON_DOCUMENT_READ_SIZE, "file-enc artifact");

/// Load plaintext bytes for file encryption.
pub fn load_plaintext_bytes(path: impl AsRef<std::path::Path>) -> Result<Vec<u8>> {
    load_bytes(path.as_ref())
}

/// Save serialized encrypted output with ordinary artifact permissions.
pub fn save_encrypted_text(path: impl AsRef<std::path::Path>, content: &str) -> Result<()> {
    save_text(path.as_ref(), content)
}

/// Save decrypted output with owner-only permissions.
pub fn save_decrypted_bytes(path: impl AsRef<std::path::Path>, content: &[u8]) -> Result<()> {
    save_bytes_restricted(path.as_ref(), content)
}

impl FileEncArtifact {
    /// Parse file-enc JSON text after format detection.
    pub fn parse(content: impl Into<String>) -> Result<Self> {
        ArtifactText::parse(content, FILE_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Load file-enc JSON from a path.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ArtifactText::load(path, FILE_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Load file-enc text through a fixed directory capability.
    pub(crate) fn load_at<D>(dir: &D, name: &str) -> Result<Self>
    where
        D: DirectoryFd,
    {
        let content =
            load_text_with_limit_at(dir, name, MAX_JSON_DOCUMENT_READ_SIZE, "file-enc artifact")?;
        let source_name = format_path_relative_to_cwd(&dir.path().join(name));
        FileEncContent::detect_with_source(content, source_name)
            .map(|content| Self::from_text(ArtifactText::from_content(content)))
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
            .map(|inner| VerifiedFileEncArtifact::from_inner(self.text.content().clone(), inner))
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
    pub(crate) fn from_inner(content: FileEncContent, inner: VerifiedFileEncDocument) -> Self {
        Self { content, inner }
    }

    pub(crate) fn inner(&self) -> &VerifiedFileEncDocument {
        &self.inner
    }

    pub(crate) fn content(&self) -> &FileEncContent {
        &self.content
    }

    pub(crate) fn binding_digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.content.as_str().as_bytes()).into())
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
        let master_key = unwrap_master_key_for_file_with_context(
            artifact.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
        )?;
        let key_info = master_key.key_info.clone();
        verify_file_key_possession(artifact.inner(), master_key.value)?;
        let warnings = collect_file_read_warnings(artifact.inner().proof(), &key_info, options)?;
        Ok(Self {
            artifact: Cow::Borrowed(artifact),
            key_ctx,
            warnings,
        })
    }

    pub(crate) fn from_authorized_owned(
        artifact: VerifiedFileEncArtifact,
        key_ctx: &'a KeyContext,
        options: OperationOptions,
    ) -> Result<Self> {
        let master_key = unwrap_master_key_for_file_with_context(
            artifact.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
        )?;
        let key_info = master_key.key_info.clone();
        verify_file_key_possession(artifact.inner(), master_key.value)?;
        let warnings = collect_file_read_warnings(artifact.inner().proof(), &key_info, options)?;
        Ok(Self {
            artifact: Cow::Owned(artifact),
            key_ctx,
            warnings,
        })
    }

    /// Return signature and local key warnings produced during authorization.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
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

fn collect_file_read_warnings(
    proof: &SignatureVerificationProof,
    key_info: &DecryptionKeyInfo,
    options: OperationOptions,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    push_signature_verification_warnings(&mut warnings, proof, Some(&key_info.key_identity))?;
    if let Some(warning) = key_info
        .key_expiry
        .enforce_expired_usage(options.allow_expired_key())?
    {
        push_unique_warning(&mut warnings, warning);
    }
    Ok(warnings)
}
