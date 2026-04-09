// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap feature - re-encryption for kv-enc and file-enc formats.

pub(crate) mod file;
pub(crate) mod file_op;
pub(crate) mod kv;
pub(crate) mod kv_op;

use crate::feature::context::crypto::CryptoContext;
use crate::format::content::EncryptedContent;
use crate::format::token::TokenCodec;
use crate::io::keystore::signer::load_signer_public_key;
use crate::model::common::WrapItem;
use crate::model::public_key::PublicKey;
use crate::model::public_key_verified::VerifiedRecipientKey;
use crate::Result;
use std::path::Path;

/// Rewrap operation options.
#[derive(Debug, Clone)]
pub(crate) struct RewrapOptions {
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub token_codec: Option<TokenCodec>,
    pub debug: bool,
}

/// Context for rewrap operations that provides common functionality.
pub(crate) struct RewrapContext<'a> {
    options: &'a RewrapOptions,
    member_id: &'a str,
    key_ctx: &'a CryptoContext,
    target_members: Option<&'a [VerifiedRecipientKey]>,
}

/// Request for rewrapping a single encrypted artifact.
#[derive(Clone, Copy)]
pub struct RewrapRequest<'a> {
    pub member_id: &'a str,
    pub key_ctx: &'a CryptoContext,
    pub workspace_root: Option<&'a Path>,
    pub target_members: Option<&'a [VerifiedRecipientKey]>,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub debug: bool,
}

impl<'a> RewrapContext<'a> {
    pub(crate) fn new(
        options: &'a RewrapOptions,
        member_id: &'a str,
        key_ctx: &'a CryptoContext,
        target_members: Option<&'a [VerifiedRecipientKey]>,
    ) -> Self {
        Self {
            options,
            member_id,
            key_ctx,
            target_members,
        }
    }

    /// Load signer's public key for embedding in signatures.
    pub(crate) fn load_signer_pub(&self) -> Result<PublicKey> {
        load_signer_public_key(self.key_ctx.pub_key_source.as_ref(), self.member_id)
    }

    pub(crate) fn options(&self) -> &'a RewrapOptions {
        self.options
    }

    pub(crate) fn key_ctx(&self) -> &'a CryptoContext {
        self.key_ctx
    }

    pub(crate) fn target_members(&self) -> Option<&'a [VerifiedRecipientKey]> {
        self.target_members
    }
}

/// Trait for rewrap executors that can perform rewrap operations.
pub(crate) trait RewrapExecutor {
    /// Return the current recipients list from the encrypted file.
    /// - file-enc: rid fields from protected.wrap
    /// - kv-enc: result of extract_recipients_from_wrap(&wrap_data)
    fn current_recipients(&self) -> Vec<String>;

    /// Add recipients to the encrypted file (wrap only, MK/DEK unchanged).
    ///
    /// `recipients` are plain member ID strings.
    fn add_recipients(&mut self, recipients: &[String]) -> Result<()>;

    /// Refresh wrap items for recipients whose target kid changed.
    fn refresh_recipients(&mut self, recipients: &[String]) -> Result<()>;

    /// Remove recipients from the encrypted file.
    ///
    /// - file-enc: removes wrap items and records in removed_recipients (MK/DEK unchanged)
    /// - kv-enc: full re-encryption with new MK/DEK, records in removed_recipients
    ///
    /// `recipients` are plain member ID strings.
    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()>;

    /// Rotate master key / content key (full re-encryption).
    fn rotate_key(&mut self) -> Result<()>;

    /// Clear the disclosure history.
    fn clear_disclosure_history(&mut self) -> Result<()>;

    /// Finalize and sign the encrypted file, returning the final content.
    fn finalize(self) -> Result<String>;
}

/// Execute rewrap operations based on options.
///
/// Computes the diff between the file's current recipients and target_recipients (@all),
/// applies remove first then add, then optional rotate-key and clear-disclosure-history.
pub(crate) fn execute_rewrap_operations<E: RewrapExecutor>(
    mut executor: E,
    options: &RewrapOptions,
    target_recipients: &[String],
    stale_recipients: &[String],
) -> Result<String> {
    let current = executor.current_recipients();

    // Remove first, then add (spec requires this order)
    let removed: Vec<String> = current
        .iter()
        .filter(|r| !target_recipients.contains(r))
        .cloned()
        .collect();
    let added: Vec<String> = target_recipients
        .iter()
        .filter(|r| !current.contains(*r))
        .cloned()
        .collect();

    if !removed.is_empty() {
        executor.remove_recipients(&removed)?;
    }
    if !stale_recipients.is_empty() {
        executor.refresh_recipients(stale_recipients)?;
    }
    if !added.is_empty() {
        executor.add_recipients(&added)?;
    }
    if options.rotate_key {
        executor.rotate_key()?;
    }
    if options.clear_disclosure_history {
        executor.clear_disclosure_history()?;
    }

    executor.finalize()
}

pub(crate) fn collect_stale_recipient_ids(
    current_wrap: &[WrapItem],
    target_members: &[VerifiedRecipientKey],
) -> Vec<String> {
    target_members
        .iter()
        .filter_map(|member| {
            let protected = &member.document().protected;
            current_wrap
                .iter()
                .find(|wrap| wrap.rid == protected.member_id)
                .filter(|wrap| wrap.kid != protected.kid)
                .map(|_| protected.member_id.clone())
        })
        .collect()
}

pub fn rewrap_content(content: &EncryptedContent, request: &RewrapRequest<'_>) -> Result<String> {
    let options = RewrapOptions {
        rotate_key: request.rotate_key,
        clear_disclosure_history: request.clear_disclosure_history,
        token_codec: match content {
            EncryptedContent::FileEnc(_) => None,
            EncryptedContent::KvEnc(_) => Some(TokenCodec::JsonJcs),
        },
        debug: request.debug,
    };

    match content {
        EncryptedContent::FileEnc(file_content) => file::rewrap_file_document(
            &options,
            file_content,
            request.member_id,
            request.key_ctx,
            request.workspace_root,
            request.target_members,
        ),
        EncryptedContent::KvEnc(kv_content) => kv::rewrap_kv_document(
            &options,
            kv_content,
            request.member_id,
            request.key_ctx,
            request.workspace_root,
            request.target_members,
        ),
    }
}
