// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap operations for kv-enc v1 format.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::kv::rewrite_session::{KvRecipientRewriteRequest, VerifiedKvRewriteSession};
use crate::feature::recipient::{check_recipient_exists, validate_not_empty_recipients};
use crate::feature::rewrap::kv_op::recipients::{add_kv_recipients, rewrite_kv_recipient_wraps};
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::document::KvDocumentDraft;
use crate::format::kv::enc::canonical::extract_recipients_from_wrap;
use crate::model::common::WrapItem;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::time::generate_current_timestamp;
use crate::Result;
use tracing::warn;

use super::{
    rewrap_document_with_common_skeleton, RewrapContext, RewrapDocumentAdapter, RewrapExecutor,
    RewrapOptions, VerifiedRewrapDocument,
};

/// Executor for kv-enc rewrap operations.
struct KvRewrapExecutor<'a> {
    session: VerifiedKvRewriteSession<'a>,
    doc: KvDocumentDraft,
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
            self.ctx.target_members(),
            self.ctx.options().debug,
        )?;
        self.update_timestamp()
    }

    fn rewrite_recipient_wraps(&mut self, recipients: &[String]) -> Result<()> {
        let sid = self.doc.head().sid;
        let master_key = self.session.unwrap_master_key()?;
        rewrite_kv_recipient_wraps(
            &sid,
            self.doc.wrap_mut(),
            recipients,
            &master_key,
            self.ctx.target_members(),
            self.ctx.options().debug,
        )?;
        self.update_timestamp()
    }

    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()> {
        let mut current_recipients = self.session.current_recipients();
        for recipient in recipients {
            if !check_recipient_exists(&current_recipients, recipient) {
                warn!(
                    "[CRYPTO] Warning: {} is not a recipient, skipping",
                    recipient
                );
            }
        }
        current_recipients.retain(|recipient| !recipients.contains(recipient));
        validate_not_empty_recipients(&current_recipients)?;
        let new_content = self.session.rewrap_kv_with_recipients(
            Some(self.ctx.target_members()),
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
        let new_content = self.session.rewrap_kv_with_recipients(
            Some(self.ctx.target_members()),
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
        self.update_timestamp()?;
        let master_key = self.session.unwrap_master_key()?;
        self.session.sign(self.doc, &master_key)
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
            ctx.member_handle,
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
            self.ctx.member_handle,
            self.ctx.key_ctx(),
            self.ctx.options().token_codec,
            self.ctx.options().debug,
        )?;
        let kv_doc = self.session.document();
        self.doc = self.session.build_unsigned(kv_doc.head().clone())?;
        Ok(())
    }

    fn update_timestamp(&mut self) -> Result<()> {
        self.doc.set_updated_at(generate_current_timestamp()?);
        Ok(())
    }
}

struct KvRewrapAdapter;

impl VerifiedRewrapDocument for VerifiedKvEncDocument {
    fn current_wrap_items(&self) -> &[WrapItem] {
        &self.document().wrap.wrap
    }
}

impl RewrapDocumentAdapter for KvRewrapAdapter {
    type Content = KvEncContent;
    type Verified = VerifiedKvEncDocument;
    type Executor<'ctx> = KvRewrapExecutor<'ctx>;

    fn verify_content(content: &Self::Content, debug: bool) -> Result<Self::Verified> {
        verify_kv_content(content, debug)
    }

    fn build_executor<'ctx>(
        verified: Self::Verified,
        ctx: &'ctx RewrapContext<'ctx>,
    ) -> Result<Self::Executor<'ctx>> {
        KvRewrapExecutor::new_from_verified(verified, ctx)
    }
}

/// Rewrap kv-enc v1 content.
pub fn rewrap_kv_document(
    options: &RewrapOptions,
    content: &KvEncContent,
    member_handle: &str,
    key_ctx: &CryptoContext,
    target_members: &[VerifiedRecipientKey],
) -> Result<String> {
    rewrap_document_with_common_skeleton::<KvRewrapAdapter>(
        options,
        content,
        member_handle,
        key_ctx,
        target_members,
    )
}
