// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! kv-enc artifact facade.

use std::collections::BTreeMap;
use std::path::Path;

use crate::feature::kv::decrypt::{
    decrypt_kv_document_with_context, decrypt_kv_single_entry_with_context,
};
use crate::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot,
    KvWriteContext,
};
use crate::feature::kv::query::{
    decode_decrypted_kv_value, decode_decrypted_kv_values, list_kv_keys_with_disclosed,
};
use crate::feature::kv::types::KvInputEntry as InternalKvInputEntry;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::support::fs::atomic::save_text;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::{Error, ErrorKind, Result};

use super::key::{KeyContext, RecipientKeys};
use super::operation::OperationOptions;
use super::secret::SecretString;
use super::trust::RecipientSetSubject;

/// Parsed kv-enc artifact.
#[derive(Debug, Clone)]
pub struct KvEncArtifact {
    content: KvEncContent,
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

impl KvEncArtifact {
    /// Parse kv-enc text after format detection.
    pub fn parse(content: impl Into<String>) -> Result<Self> {
        Ok(Self {
            content: KvEncContent::detect(content.into())?,
        })
    }

    /// Load kv-enc text from a path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = load_text_with_limit(
            path.as_ref(),
            MAX_JSON_DOCUMENT_READ_SIZE,
            "kv-enc artifact",
        )?;
        Self::parse(content)
    }

    /// Save the artifact text.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        save_text(path.as_ref(), self.as_str())
    }

    /// Verify the artifact signature.
    pub fn verify(&self, options: OperationOptions) -> Result<VerifiedKvEncArtifact> {
        verify_kv_content(&self.content, options.debug())
            .map(|inner| VerifiedKvEncArtifact::from_inner(self.content.clone(), inner))
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
        list_kv_keys_with_disclosed(&self.content).map(|entries| {
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
        self.content.as_str()
    }

    fn rewrite_entries(
        existing: Option<&KvEncContent>,
        entries: Vec<KvInputEntry>,
        recipients: &RecipientKeys,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<Self> {
        let recipient_snapshot = KvRecipientSnapshot {
            member_handles: recipients.handles().to_vec(),
            verified_members: recipients.keys().to_vec(),
        };
        let ctx = KvWriteContext::new(
            &key_ctx.inner().member_handle,
            key_ctx.inner(),
            options.debug(),
        );
        let result = set_kv_entry_with_recipients(
            existing,
            &entries
                .into_iter()
                .map(KvInputEntry::into_internal)
                .collect::<Vec<_>>(),
            &recipient_snapshot,
            &ctx,
        )?;
        Ok(Self {
            content: result.encrypted,
        })
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
        let recipient_snapshot = KvRecipientSnapshot {
            member_handles: recipients.handles().to_vec(),
            verified_members: recipients.keys().to_vec(),
        };
        let ctx = KvWriteContext::new(
            &key_ctx.inner().member_handle,
            key_ctx.inner(),
            options.debug(),
        );
        let content =
            unset_kv_entry_with_recipients(&self.content, key, &recipient_snapshot, &ctx)?;
        KvEncArtifact::parse(content)
    }

    /// Decrypt one entry value from a verified artifact.
    pub fn decrypt_entry(
        &self,
        key_ctx: &KeyContext,
        key: &str,
        options: OperationOptions,
    ) -> Result<SecretString> {
        let value = decrypt_kv_single_entry_with_context(
            self.inner(),
            key_ctx.member_handle(),
            key_ctx.inner(),
            key,
            options.debug(),
        )
        .map(|result| result.value)
        .map_err(|error| build_key_not_found_error(error, key))?;
        decode_decrypted_kv_value(key, value).map(SecretString::from_inner)
    }

    /// Decrypt all entry values from a verified artifact.
    pub fn decrypt_entries(
        &self,
        key_ctx: &KeyContext,
        options: OperationOptions,
    ) -> Result<BTreeMap<String, SecretString>> {
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

    /// Return the secret entry value.
    pub fn value(&self) -> &SecretString {
        &self.value
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

fn build_key_not_found_error(error: Error, key: &str) -> Error {
    if error.kind() == ErrorKind::InvalidOperation {
        return Error::build_invalid_operation_error(format!("Key '{}' not found", key));
    }
    error
}
