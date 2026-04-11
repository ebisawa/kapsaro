// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap operations for kv-enc v3 format.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::kv::document::UnsignedKvDocument;
use crate::feature::kv::rewrite_session::{KvRecipientRewriteRequest, VerifiedKvRewriteSession};
use crate::feature::recipient::{
    check_recipient_exists, collect_target_recipient_ids, resolve_verified_recipients,
    validate_not_empty_recipients, warn_recipient_not_found,
};
use crate::feature::rewrap::kv_op::recipients::{add_kv_recipients, refresh_kv_recipients};
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::enc::canonical::extract_recipients_from_wrap;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;
use std::path::Path;

use super::{
    collect_stale_recipient_ids, execute_rewrap_operations, RewrapContext, RewrapExecutor,
    RewrapOptions,
};

/// Executor for kv-enc rewrap operations.
struct KvRewrapExecutor<'a> {
    session: VerifiedKvRewriteSession<'a>,
    doc: UnsignedKvDocument,
    ctx: &'a RewrapContext<'a>,
}

impl<'a> RewrapExecutor for KvRewrapExecutor<'a> {
    fn current_recipients(&self) -> Vec<String> {
        extract_recipients_from_wrap(self.doc.wrap())
    }

    fn add_recipients(&mut self, recipients: &[String]) -> Result<()> {
        let sid = self.doc.head().sid;
        let master_key = self.session.unwrap_master_key()?;
        add_kv_recipients(
            &sid,
            self.doc.wrap_mut(),
            recipients,
            &master_key,
            self.ctx.key_ctx(),
            self.ctx.target_members(),
            self.ctx.options().debug,
        )?;
        self.doc.update_timestamp()
    }

    fn refresh_recipients(&mut self, recipients: &[String]) -> Result<()> {
        let sid = self.doc.head().sid;
        let master_key = self.session.unwrap_master_key()?;
        refresh_kv_recipients(
            &sid,
            self.doc.wrap_mut(),
            recipients,
            &master_key,
            self.ctx.key_ctx(),
            self.ctx.target_members(),
            self.ctx.options().debug,
        )?;
        self.doc.update_timestamp()
    }

    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()> {
        let mut current_recipients = self.session.current_recipients();
        for recipient in recipients {
            if !check_recipient_exists(&current_recipients, recipient) {
                warn_recipient_not_found(recipient);
            }
        }
        current_recipients.retain(|recipient| !recipients.contains(recipient));
        validate_not_empty_recipients(&current_recipients)?;
        let new_content = self.session.reencrypt_with_recipients(
            self.ctx.target_members(),
            KvRecipientRewriteRequest {
                new_recipients: &current_recipients,
                removed_recipients: recipients,
                disclosed: true,
                preserve_removed_history: true,
            },
        )?;

        self.rebuild_from_content(&new_content)?;
        Ok(())
    }

    fn rotate_key(&mut self) -> Result<()> {
        let current_recipients = self.session.current_recipients();
        let new_content = self.session.reencrypt_with_recipients(
            self.ctx.target_members(),
            KvRecipientRewriteRequest {
                new_recipients: &current_recipients,
                removed_recipients: &[],
                disclosed: self.session.disclosed(),
                preserve_removed_history: false,
            },
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
        let doc = session.build_unsigned(kv_doc.head().clone())?;

        Ok(Self { session, doc, ctx })
    }

    /// Rebuild the document from new kv-enc content (used after remove/rotate).
    fn rebuild_from_content(&mut self, content: &str) -> Result<()> {
        let kv_content = KvEncContent::new_unchecked(content.to_string());
        self.session = VerifiedKvRewriteSession::load(
            &kv_content,
            self.ctx.member_id,
            self.ctx.key_ctx(),
            self.ctx.options().token_codec,
            self.ctx.options().debug,
        )?;
        let kv_doc = self.session.document();
        self.doc = self.session.build_unsigned(kv_doc.head().clone())?;
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
    target_members: Option<&[VerifiedRecipientKey]>,
) -> Result<String> {
    let all_members = collect_target_recipient_ids(workspace_root, target_members)?;
    let verified_target_members =
        resolve_verified_recipients(target_members, key_ctx, &all_members, options.debug)?;

    let verified = verify_kv_content(content, options.debug)?;
    let stale_recipients =
        collect_stale_recipient_ids(&verified.document().wrap.wrap, &verified_target_members);

    let ctx = RewrapContext::new(options, member_id, key_ctx, Some(&verified_target_members));
    let executor = KvRewrapExecutor::new_from_verified(verified, &ctx)?;
    execute_rewrap_operations(executor, options, &all_members, &stale_recipients)
}
