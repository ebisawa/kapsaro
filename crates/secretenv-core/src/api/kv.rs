// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! kv-enc artifact facade.

use std::collections::BTreeMap;

use crate::api::artifact_text::{ArtifactLoadPolicy, ArtifactText};
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
        ArtifactText::parse(content).map(Self::from_text)
    }

    /// Load kv-enc text from a path.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ArtifactText::load(path, KV_ENC_LOAD_POLICY).map(Self::from_text)
    }

    /// Save the artifact text.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        self.text.save(path)
    }

    /// Verify the artifact signature.
    pub fn verify(&self, options: OperationOptions) -> Result<VerifiedKvEncArtifact> {
        verify_kv_content_for_operation(
            self.text.content(),
            options.debug(),
            options.allow_expired_key(),
        )
        .map(|inner| VerifiedKvEncArtifact::from_inner(self.text.content().clone(), inner))
    }

    /// Encrypt entries to a new signed kv-enc artifact.
    pub fn encrypt_entries(
        entries: Vec<KvInputEntry>,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<Self> {
        Self::rewrite_entries(None, entries, recipients, key_ctx, options)
    }

    /// List entry keys without decrypting values.
    pub fn list_entry_keys(&self) -> Result<Vec<KvDisclosedEntry>> {
        list_kv_keys_with_disclosed(self.text.content()).map(|entries| {
            entries
                .into_iter()
                .map(|entry| KvDisclosedEntry {
                    key: entry.key,
                    disclosed: entry.disclosed,
                })
                .collect()
        })
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
        options: OperationOptions,
    ) -> Result<Self> {
        let input = build_kv_write_input(recipients, key_ctx, options);
        let internal_entries = into_internal_entries(entries);
        let result = set_kv_entry_with_recipients(
            existing,
            &internal_entries,
            &input.recipients,
            &input.ctx,
        )?;
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

    /// Extract the recipient-set subject for trust policy evaluation.
    pub fn recipient_set_subject(&self) -> Result<RecipientSetSubject> {
        RecipientSetSubject::from_verified_kv(self.inner())
    }

    /// Add or replace entries in a verified kv-enc artifact.
    pub fn set_entries(
        &self,
        entries: Vec<KvInputEntry>,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<KvEncArtifact> {
        KvEncArtifact::rewrite_entries(Some(&self.content), entries, recipients, key_ctx, options)
    }

    /// Remove an entry from a verified kv-enc artifact.
    pub fn unset_entry(
        &self,
        key: &str,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<KvEncArtifact> {
        let input = build_kv_write_input(recipients, key_ctx, options);
        let content =
            unset_kv_entry_with_recipients(&self.content, key, &input.recipients, &input.ctx)?;
        KvEncArtifact::parse(content)
    }

    /// Decrypt one entry value from a verified artifact.
    pub fn decrypt_entry(
        &self,
        key_ctx: &KeyContext,
        key: &str,
        options: OperationOptions,
    ) -> Result<SecretString> {
        enforce_key_context_expiry(self, key_ctx, options)?;
        let value = decrypt_kv_single_entry_with_context(
            self.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
            key,
            options.debug(),
        )
        .map(|result| result.value)
        .map_err(|error| normalize_key_not_found_error(error, key))?;
        decode_decrypted_kv_value(key, value).map(SecretString::from_inner)
    }

    /// Decrypt all entry values from a verified artifact.
    pub fn decrypt_entries(
        &self,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<BTreeMap<String, SecretString>> {
        enforce_key_context_expiry(self, key_ctx, options)?;
        let values = decrypt_kv_document_with_context(
            self.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
            options.debug(),
        )?
        .value;
        decode_decrypted_kv_values(values).map(|values| {
            values
                .into_iter()
                .map(|(key, value)| (key, SecretString::from_inner(value)))
                .collect()
        })
    }
}

fn enforce_key_context_expiry(
    artifact: &VerifiedKvEncArtifact,
    key_ctx: &KeyContext,
    options: OperationOptions,
) -> Result<()> {
    key_ctx.enforce_decryption_key_not_expired(&artifact.inner().document().wrap().wrap, options)
}

fn build_kv_write_input<'a>(
    recipients: &RecipientKeys,
    key_ctx: &'a KeyContext,
    options: OperationOptions,
) -> KvFacadeWriteInput<'a> {
    KvFacadeWriteInput {
        recipients: KvRecipientSnapshot {
            member_handles: recipients.handles().to_vec(),
            verified_members: recipients.keys().to_vec(),
        },
        ctx: KvWriteContext::new(key_ctx.member_handle(), key_ctx.inner(), options.debug()),
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
