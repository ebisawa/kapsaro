// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap operations for kv-enc v3 format.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::kv::document::UnsignedKvDocument;
use crate::feature::kv::rewrite_session::VerifiedKvRewriteSession;
use crate::feature::rewrap::kv_op::recipients::{add_kv_recipients, remove_kv_recipients};
use crate::feature::rewrap::kv_op::rotate::rotate_kv_key;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::enc::canonical::extract_recipients_from_wrap;
use crate::io::workspace::members::list_active_member_ids;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::{Error, Result};
use std::path::Path;

use super::{execute_rewrap_operations, RewrapContext, RewrapExecutor, RewrapOptions};

/// Executor for kv-enc rewrap operations.
struct KvRewrapExecutor<'a> {
    session: VerifiedKvRewriteSession<'a>,
    doc: UnsignedKvDocument,
    ctx: &'a RewrapContext<'a>,
    original_content: String,
}

impl<'a> RewrapExecutor for KvRewrapExecutor<'a> {
    fn current_recipients(&self) -> Vec<String> {
        extract_recipients_from_wrap(self.doc.wrap())
    }

    fn add_recipients(&mut self, recipients: &[String]) -> Result<()> {
        let sid = self.doc.head().sid;
        add_kv_recipients(
            &sid,
            self.doc.wrap_mut(),
            recipients,
            self.ctx.key_ctx(),
            self.ctx.options().debug,
        )?;
        self.doc.update_timestamp()
    }

    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()> {
        let new_content = remove_kv_recipients(
            &self.original_content,
            recipients,
            self.ctx.key_ctx(),
            self.ctx.options().debug,
        )?;

        self.rebuild_from_content(&new_content)?;
        Ok(())
    }

    fn rotate_key(&mut self) -> Result<()> {
        let new_content = rotate_kv_key(
            &self.original_content,
            self.ctx.key_ctx(),
            self.ctx.options().debug,
        )?;

        self.rebuild_from_content(&new_content)?;
        Ok(())
    }

    fn clear_disclosure_history(&mut self) -> Result<()> {
        self.doc.wrap_mut().removed_recipients = None;
        self.doc.clear_disclosed_flags()
    }

    fn finalize(mut self) -> Result<String> {
        self.doc.update_timestamp()?;
        self.session.sign(self.doc)
    }
}

impl<'a> KvRewrapExecutor<'a> {
    /// Create a new executor from a verified kv-enc document.
    fn new_from_verified(
        verified: VerifiedKvEncDocument,
        ctx: &'a RewrapContext<'a>,
    ) -> Result<Self> {
        let session = VerifiedKvRewriteSession::from_verified(
            verified,
            ctx.member_id,
            ctx.key_ctx(),
            ctx.options().token_codec,
            ctx.options().debug,
        );
        let kv_doc = session.document();
        let original_content = kv_doc.content().to_string();
        let doc = session.build_unsigned(kv_doc.head().clone())?;

        Ok(Self {
            session,
            doc,
            ctx,
            original_content,
        })
    }

    /// Rebuild the document from new kv-enc content (used after remove/rotate).
    fn rebuild_from_content(&mut self, content: &str) -> Result<()> {
        self.doc = self.session.rebuild_unsigned_from_content(content)?;
        self.original_content = content.to_string();
        Ok(())
    }
}

/// Rewrap kv-enc v3 content.
pub fn rewrap_kv_document(
    options: &RewrapOptions,
    content: &KvEncContent,
    member_id: &str,
    key_ctx: &CryptoContext,
    workspace_root: Option<&Path>,
) -> Result<String> {
    let workspace_root = workspace_root.ok_or_else(|| Error::Config {
        message: "rewrap requires a workspace".to_string(),
    })?;
    let all_members = list_active_member_ids(workspace_root)?;

    let verified = verify_kv_content(content, key_ctx.workspace_path.as_deref(), options.debug)?;

    let ctx = RewrapContext::new(options, member_id, key_ctx);
    let executor = KvRewrapExecutor::new_from_verified(verified, &ctx)?;
    execute_rewrap_operations(executor, options, &all_members)
}
