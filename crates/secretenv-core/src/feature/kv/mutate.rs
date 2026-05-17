// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Mutating operations for kv-enc documents.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::wrap::{build_wraps_for_recipients, WrapFormat};
use crate::format::content::KvEncContent;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::header::KvWrap;
use crate::model::kv_enc::line::KvEncLine;
use crate::model::public_key::VerifiedRecipientKey;
use crate::{Error, Result};
use std::collections::HashMap;

use super::entry_codec::build_entry_tokens;
use super::header::build_updated_header;
use super::types::KvInputEntry;

/// Result of kv set operation.
pub struct KvSetResult {
    pub encrypted: KvEncContent,
    pub recipients: Vec<String>,
}

/// Context for kv write operations (set/unset).
pub struct KvWriteContext<'a> {
    pub member_handle: &'a str,
    pub key_ctx: &'a CryptoContext,
    pub token_codec: Option<TokenCodec>,
    pub verbose: bool,
}

impl<'a> KvWriteContext<'a> {
    /// Build a new KvWriteContext.
    pub fn new(member_handle: &'a str, key_ctx: &'a CryptoContext, verbose: bool) -> Self {
        Self {
            member_handle,
            key_ctx,
            token_codec: None,
            verbose,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KvRecipientSnapshot {
    pub member_handles: Vec<String>,
    pub verified_members: Vec<VerifiedRecipientKey>,
}

pub fn set_kv_entry_with_recipients(
    existing_content: Option<&KvEncContent>,
    entries: &[KvInputEntry],
    recipients: &KvRecipientSnapshot,
    ctx: &KvWriteContext<'_>,
) -> Result<KvSetResult> {
    match existing_content {
        None => set_kv_new_file(entries, recipients, ctx),
        Some(content) => set_kv_existing_file(content, entries, recipients, ctx),
    }
}

pub fn unset_kv_entry_with_recipients(
    content: &KvEncContent,
    key: &str,
    recipients: &KvRecipientSnapshot,
    ctx: &KvWriteContext<'_>,
) -> Result<String> {
    rewrite_existing_kv_content(content, recipients, ctx, |unsigned, session, _| {
        if !contains_key(session.document().lines(), key) {
            return Err(Error::build_invalid_operation_error(format!(
                "Key '{}' not found",
                key
            )));
        }
        unsigned.unset_entry(key);
        Ok(())
    })
}

fn set_kv_new_file(
    entries: &[KvInputEntry],
    recipients: &KvRecipientSnapshot,
    ctx: &KvWriteContext<'_>,
) -> Result<KvSetResult> {
    let codec = ctx.token_codec.unwrap_or(TokenCodec::JsonJcs);
    let kv_map: HashMap<String, &crate::support::secret::SecretString> = entries
        .iter()
        .map(|entry| (entry.key.clone(), &entry.value))
        .collect();
    let encrypted = super::rewrite_session::encrypt_kv_map_with_key_context(
        &kv_map,
        &recipients.verified_members,
        ctx.key_ctx,
        codec,
        false,
        |_| Ok(()),
        ctx.verbose,
    )?;
    Ok(KvSetResult {
        encrypted: KvEncContent::new_unchecked(encrypted),
        recipients: recipients.member_handles.clone(),
    })
}

fn set_kv_existing_file(
    content: &KvEncContent,
    entries: &[KvInputEntry],
    recipients: &KvRecipientSnapshot,
    ctx: &KvWriteContext<'_>,
) -> Result<KvSetResult> {
    let encrypted =
        rewrite_existing_kv_content(content, recipients, ctx, |unsigned, session, master_key| {
            let entry_tokens = build_entry_tokens(
                entries,
                master_key,
                &session.document().head.sid,
                session.token_codec(),
                ctx.verbose,
                "set_kv_entry",
            )?;
            let new_entries: HashMap<&str, &str> = entry_tokens
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect();
            unsigned.set_entries(&new_entries);
            Ok(())
        })?;
    Ok(KvSetResult {
        encrypted: KvEncContent::new_unchecked(encrypted),
        recipients: recipients.member_handles.clone(),
    })
}

fn rewrite_existing_kv_content<F>(
    content: &KvEncContent,
    recipients: &KvRecipientSnapshot,
    ctx: &KvWriteContext<'_>,
    mutate_unsigned: F,
) -> Result<String>
where
    F: FnOnce(
        &mut crate::feature::kv::document::KvDocumentDraft,
        &super::rewrite_session::VerifiedKvRewriteSession<'_>,
        &crate::crypto::types::keys::MasterKey,
    ) -> Result<()>,
{
    let session = super::rewrite_session::VerifiedKvRewriteSession::load(
        content,
        ctx.member_handle,
        ctx.key_ctx,
        ctx.token_codec,
        ctx.verbose,
    )?;
    let head = build_updated_header(session.document())?;
    let sid = session.document().head.sid;
    let removed_recipients = session.document().wrap.removed_recipients.clone();
    let master_key = session.unwrap_master_key()?;
    let mut unsigned = session.build_unsigned(head)?;
    mutate_unsigned(&mut unsigned, &session, &master_key)?;
    unsigned.set_wrap(build_current_wrap(
        &sid,
        recipients,
        &master_key,
        removed_recipients,
        ctx.verbose,
    )?);
    session.sign(unsigned)
}

fn build_current_wrap(
    sid: &uuid::Uuid,
    recipients: &KvRecipientSnapshot,
    master_key: &crate::crypto::types::keys::MasterKey,
    removed_recipients: Option<Vec<crate::model::common::RemovedRecipient>>,
    debug: bool,
) -> Result<KvWrap> {
    let wrap = build_wraps_for_recipients(
        &recipients.verified_members,
        sid,
        master_key,
        WrapFormat::Kv,
        debug,
    )?;
    Ok(KvWrap {
        wrap,
        removed_recipients,
    })
}

fn contains_key(lines: &[KvEncLine], key: &str) -> bool {
    lines
        .iter()
        .any(|line| matches!(line, KvEncLine::KV { key: existing, .. } if existing == key))
}
