// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! kv-enc artifact facade.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

use crate::api::artifact_text::{ArtifactLoadPolicy, ArtifactText};
use crate::feature::envelope::key_possession::verify_kv_key_possession;
use crate::feature::envelope::unwrap::unwrap_master_key_for_kv_with_context;
use crate::feature::kv::decrypt::{
    decrypt_kv_document_with_context, decrypt_kv_single_entry_with_context,
};
use crate::feature::kv::error::normalize_key_not_found_error;
use crate::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot,
    KvWriteContext,
};
use crate::feature::kv::query::{
    decode_decrypted_kv_value, decode_decrypted_kv_values, list_kv_keys_with_disclosed,
};
use crate::feature::kv::types::KvInputEntry as InternalKvInputEntry;
use crate::feature::verify::kv::signature::verify_kv_content_for_operation;
use crate::format::content::KvEncContent;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::support::limits::MAX_KV_ENC_FILE_SIZE;
use crate::Result;

use super::key::{KeyContext, RecipientKeys};
use super::operation::OperationOptions;
use super::secret::SecretString;
use super::trust::RecipientSetSubject;

/// Parsed kv-enc artifact.
#[derive(Debug, Clone)]
pub struct KvEncArtifact {
    text: ArtifactText<KvEncContent>,
}

/// Signature-verified kv-enc artifact.
pub struct VerifiedKvEncArtifact {
    content: KvEncContent,
    inner: VerifiedKvEncDocument,
}

/// Trust-authorized kv-enc artifact bound to one read operation and key.
pub struct TrustedKvEncArtifact<'a> {
    artifact: &'a VerifiedKvEncArtifact,
    key_ctx: &'a KeyContext,
    operation: KvReadOperation,
}

/// Trust-authorized KV mutation bound to one artifact, recipient set, key, and operation.
pub struct AuthorizedKvMutation<'a> {
    artifact: &'a VerifiedKvEncArtifact,
    recipients: &'a RecipientKeys,
    key_ctx: &'a KeyContext,
    operation: KvMutationOperation,
}

/// Authorized KV read operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvReadOperation {
    Entry(String),
    Entries,
    List,
    Environment,
}

/// Authorized KV mutation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvMutationOperation {
    Set,
    Unset,
}

/// Secret entry input for kv-enc writes.
#[derive(Debug)]
pub struct KvInputEntry {
    key: String,
    value: SecretString,
}

/// KV key listing entry with disclosure metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvDisclosedEntry {
    key: String,
    disclosed: bool,
}

struct KvFacadeWriteInput<'a> {
    recipients: KvRecipientSnapshot,
    ctx: KvWriteContext<'a>,
}

const KV_ENC_LOAD_POLICY: ArtifactLoadPolicy =
    ArtifactLoadPolicy::new(MAX_KV_ENC_FILE_SIZE, "kv-enc artifact");

impl KvEncArtifact {
    /// Parse kv-enc text after format detection.
    pub fn parse(content: impl Into<String>) -> Result<Self> {
        ArtifactText::parse(content, KV_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Load kv-enc text from a path.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ArtifactText::load(path, KV_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Load kv-enc text from a bounded UTF-8 reader.
    pub fn load_reader(reader: impl Read, source_name: impl Into<String>) -> Result<Self> {
        ArtifactText::load_reader(reader, source_name, KV_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Save the artifact text.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        self.text.save(path)
    }

    /// Verify the artifact signature.
    pub fn verify(&self, options: OperationOptions) -> Result<VerifiedKvEncArtifact> {
        verify_kv_content_for_operation(self.text.content(), options.allow_expired_key())
            .map(|inner| VerifiedKvEncArtifact::from_inner(self.text.content().clone(), inner))
    }

    /// Encrypt entries to a new signed kv-enc artifact.
    pub fn encrypt_entries(
        entries: Vec<KvInputEntry>,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
    ) -> Result<Self> {
        Self::rewrite_entries(None, entries, recipients, key_ctx)
    }

    /// Return the serialized artifact text.
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }

    fn rewrite_entries(
        existing: Option<&KvEncContent>,
        entries: Vec<KvInputEntry>,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
    ) -> Result<Self> {
        let internal_entries = into_internal_entries(entries);
        Self::rewrite_internal_entries(existing, &internal_entries, recipients, key_ctx)
    }

    fn rewrite_internal_entries(
        existing: Option<&KvEncContent>,
        entries: &[InternalKvInputEntry],
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
    ) -> Result<Self> {
        let input = build_kv_write_input(recipients, key_ctx);
        let result =
            set_kv_entry_with_recipients(existing, entries, &input.recipients, &input.ctx)?;
        Ok(Self::from_text(ArtifactText::from_content(
            result.encrypted,
        )))
    }

    fn from_text(text: ArtifactText<KvEncContent>) -> Self {
        Self { text }
    }
}

impl VerifiedKvEncArtifact {
    pub(crate) fn from_inner(content: KvEncContent, inner: VerifiedKvEncDocument) -> Self {
        Self { content, inner }
    }

    pub(crate) fn inner(&self) -> &VerifiedKvEncDocument {
        &self.inner
    }

    pub(crate) fn binding_digest(&self) -> [u8; 32] {
        Sha256::digest(self.content.as_str().as_bytes()).into()
    }

    /// Extract the recipient-set subject for trust policy evaluation.
    pub fn recipient_set_subject(&self) -> Result<RecipientSetSubject> {
        RecipientSetSubject::from_verified_kv(self.inner())
    }
}

impl<'a> AuthorizedKvMutation<'a> {
    pub(crate) fn from_authorized(
        artifact: &'a VerifiedKvEncArtifact,
        recipients: &'a RecipientKeys,
        key_ctx: &'a KeyContext,
        options: OperationOptions,
        operation: KvMutationOperation,
    ) -> Result<Self> {
        key_ctx.enforce_decryption_key_not_expired(
            &artifact.inner().document().wrap().wrap,
            options,
        )?;
        key_ctx.inner().enforce_signing_key_not_expired()?;
        verify_kv_key_possession_with_context(artifact, key_ctx)?;
        Ok(Self {
            artifact,
            recipients,
            key_ctx,
            operation,
        })
    }

    /// Add or replace entries using the bound artifact, recipients, and signing key.
    pub fn set_entries(&self, entries: Vec<KvInputEntry>) -> Result<KvEncArtifact> {
        let entries = into_internal_entries(entries);
        self.set_internal_entries(&entries)
    }

    pub(crate) fn set_internal_entries(
        &self,
        entries: &[InternalKvInputEntry],
    ) -> Result<KvEncArtifact> {
        self.enforce_operation("set", matches!(self.operation, KvMutationOperation::Set))?;
        KvEncArtifact::rewrite_internal_entries(
            Some(&self.artifact.content),
            entries,
            self.recipients,
            self.key_ctx,
        )
    }

    /// Remove an entry using the bound artifact, recipients, and signing key.
    pub fn unset_entry(&self, key: &str) -> Result<KvEncArtifact> {
        self.enforce_operation(
            "unset",
            matches!(self.operation, KvMutationOperation::Unset),
        )?;
        let input = build_kv_write_input(self.recipients, self.key_ctx);
        let content = unset_kv_entry_with_recipients(
            &self.artifact.content,
            key,
            &input.recipients,
            &input.ctx,
        )?;
        KvEncArtifact::parse(content)
    }

    fn enforce_operation(&self, expected: &str, matches: bool) -> Result<()> {
        if matches {
            Ok(())
        } else {
            Err(mutation_operation_mismatch(expected))
        }
    }
}

impl<'a> TrustedKvEncArtifact<'a> {
    pub(crate) fn from_authorized(
        artifact: &'a VerifiedKvEncArtifact,
        key_ctx: &'a KeyContext,
        operation: KvReadOperation,
        options: OperationOptions,
    ) -> Result<Self> {
        key_ctx.enforce_decryption_key_not_expired(
            &artifact.inner().document().wrap().wrap,
            options,
        )?;
        verify_kv_key_possession_with_context(artifact, key_ctx)?;
        Ok(Self {
            artifact,
            key_ctx,
            operation,
        })
    }

    /// List key names and disclosure metadata after key-possession verification.
    pub fn list_entry_keys(&self) -> Result<Vec<KvDisclosedEntry>> {
        self.enforce_operation("list", matches!(self.operation, KvReadOperation::List))?;
        list_kv_keys_with_disclosed(&self.artifact.content).map(|entries| {
            entries
                .into_iter()
                .map(|entry| KvDisclosedEntry {
                    key: entry.key,
                    disclosed: entry.disclosed,
                })
                .collect()
        })
    }

    /// Decrypt the entry bound to this trust decision.
    pub fn decrypt_entry(&self) -> Result<SecretString> {
        let KvReadOperation::Entry(key) = &self.operation else {
            return Err(operation_mismatch("entry"));
        };
        let value = decrypt_kv_single_entry_with_context(
            self.artifact.inner(),
            self.key_ctx.member_handle(),
            self.key_ctx.inner(),
            key,
        )
        .map(|result| result.value)
        .map_err(|error| normalize_key_not_found_error(error, key))?;
        decode_decrypted_kv_value(key, value).map(SecretString::from_inner)
    }

    /// Decrypt all entry values for a values read operation.
    pub fn decrypt_entries(&self) -> Result<BTreeMap<String, SecretString>> {
        self.enforce_operation(
            "entries",
            matches!(self.operation, KvReadOperation::Entries),
        )?;
        self.decrypt_all_values()
    }

    /// Decrypt all values for child-process environment injection.
    pub fn decrypt_environment(&self) -> Result<BTreeMap<String, SecretString>> {
        self.enforce_operation(
            "environment",
            matches!(self.operation, KvReadOperation::Environment),
        )?;
        self.decrypt_all_values()
    }

    fn decrypt_all_values(&self) -> Result<BTreeMap<String, SecretString>> {
        let values = decrypt_kv_document_with_context(
            self.artifact.inner(),
            self.key_ctx.member_handle(),
            self.key_ctx.inner(),
        )?
        .value;
        decode_decrypted_kv_values(values).map(|values| {
            values
                .into_iter()
                .map(|(key, value)| (key, SecretString::from_inner(value)))
                .collect()
        })
    }

    fn enforce_operation(&self, expected: &str, matches: bool) -> Result<()> {
        if matches {
            Ok(())
        } else {
            Err(operation_mismatch(expected))
        }
    }
}

fn operation_mismatch(expected: &str) -> crate::Error {
    crate::Error::build_invalid_operation_error(format!(
        "Trusted KV artifact is not authorized for {expected} reads"
    ))
}

fn mutation_operation_mismatch(expected: &str) -> crate::Error {
    crate::Error::build_invalid_operation_error(format!(
        "Authorized KV mutation is not authorized for {expected} mutations"
    ))
}

fn verify_kv_key_possession_with_context(
    artifact: &VerifiedKvEncArtifact,
    key_ctx: &KeyContext,
) -> Result<()> {
    let doc = artifact.inner().document();
    let master_key = unwrap_master_key_for_kv_with_context(
        &doc.head().sid,
        &doc.wrap().wrap,
        key_ctx.member_handle(),
        key_ctx.inner(),
    )?;
    verify_kv_key_possession(artifact.inner(), master_key.value).map(|_| ())
}

fn build_kv_write_input<'a>(
    recipients: &RecipientKeys,
    key_ctx: &'a KeyContext,
) -> KvFacadeWriteInput<'a> {
    KvFacadeWriteInput {
        recipients: KvRecipientSnapshot {
            member_handles: recipients.handles().to_vec(),
            verified_members: recipients.keys().to_vec(),
        },
        ctx: KvWriteContext::new(key_ctx.member_handle(), key_ctx.inner()),
    }
}

fn into_internal_entries(entries: Vec<KvInputEntry>) -> Vec<InternalKvInputEntry> {
    entries
        .into_iter()
        .map(KvInputEntry::into_internal)
        .collect()
}

impl KvInputEntry {
    /// Build a KV input entry from a secret-bearing value.
    pub fn new(key: impl Into<String>, value: SecretString) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }

    /// Return the entry key.
    pub fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn into_secret_parts(self) -> (String, SecretString) {
        (self.key, self.value)
    }

    fn into_internal(self) -> InternalKvInputEntry {
        InternalKvInputEntry::new_secret(self.key, self.value.into_inner())
    }
}

impl KvDisclosedEntry {
    /// Return the entry key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Return whether the entry was marked as disclosed.
    pub fn disclosed(&self) -> bool {
        self.disclosed
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/api_kv_mutation_test.rs"]
mod api_kv_mutation_test;
