// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap feature - re-encryption for kv-enc and file-enc formats.

pub mod common;
pub(crate) mod file;
pub(crate) mod file_op;
pub(crate) mod kv;
pub(crate) mod kv_op;

use crate::feature::context::crypto::CryptoContext;
use crate::format::token::TokenCodec;
use crate::io::keystore::signer::load_signer_public_key;
use crate::model::public_key::PublicKey;
use crate::Result;

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
}

impl<'a> RewrapContext<'a> {
    pub(crate) fn new(
        options: &'a RewrapOptions,
        member_id: &'a str,
        key_ctx: &'a CryptoContext,
    ) -> Self {
        Self {
            options,
            member_id,
            key_ctx,
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
