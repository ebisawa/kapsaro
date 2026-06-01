// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap operations for file-enc v7 format.

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::{build_signing_context, CryptoContext};
use crate::feature::envelope::key_schedule::FileKeySchedule;
use crate::feature::envelope::signature::sign_file_document;
use crate::feature::rewrap::file_op::content_key::unwrap_verified_file_content_key;
use crate::feature::rewrap::file_op::recipients::{
    add_file_recipients, remove_file_recipients, rewrite_file_recipient_wraps,
};
use crate::feature::rewrap::file_op::rotate::rotate_file_key;
use crate::feature::verify::file::verify_file_content;
use crate::format::content::FileEncContent;
use crate::model::common::WrapItem;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::file_enc::{FileEncDocument, FileEncDocumentProtected};
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::time;
use crate::{Error, Result};

use super::{
    rewrap_document_with_common_skeleton, RewrapContext, RewrapDocumentAdapter, RewrapExecutor,
    RewrapOptions, VerifiedRewrapDocument,
};

/// Executor for file-enc rewrap operations.
struct FileRewrapExecutor<'a> {
    ctx: &'a RewrapContext<'a>,
    protected: FileEncDocumentProtected,
    verified: VerifiedFileEncDocument,
    content_key: FileContentKeyState,
}

enum FileContentKeyState {
    Unloaded,
    Original(MasterKey),
    Rotated(MasterKey),
}

impl<'a> RewrapExecutor for FileRewrapExecutor<'a> {
    fn current_recipients(&self) -> Vec<String> {
        self.protected
            .wrap
            .iter()
            .map(|w| w.recipient_handle.clone())
            .collect()
    }

    fn add_recipients(&mut self, recipients: &[String]) -> Result<()> {
        self.ensure_content_key()?;
        let content_key = self.content_key.as_ref();
        add_file_recipients(
            &mut self.protected,
            content_key,
            recipients,
            self.ctx.target_members(),
            self.ctx.options().debug,
        )
    }

    fn rewrite_recipient_wraps(&mut self, recipients: &[String]) -> Result<()> {
        self.ensure_content_key()?;
        let content_key = self.content_key.as_ref();
        rewrite_file_recipient_wraps(
            &mut self.protected,
            content_key,
            recipients,
            self.ctx.target_members(),
            self.ctx.options().debug,
        )
    }

    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()> {
        remove_file_recipients(&mut self.protected, recipients)?;
        self.rotate_key()
    }

    fn rotate_key(&mut self) -> Result<()> {
        if self.content_key.is_rotated() {
            return Ok(());
        }
        self.ensure_content_key()?;
        let content_key = rotate_file_key(
            &mut self.protected,
            &self.verified,
            self.content_key.as_ref(),
            self.ctx.target_members(),
            self.ctx.options().debug,
        )?;
        self.content_key = FileContentKeyState::Rotated(content_key);
        Ok(())
    }

    fn clear_disclosure_history(&mut self) -> Result<()> {
        self.protected.removed_recipients = None;
        Ok(())
    }

    fn finalize(self) -> Result<String> {
        let mut executor = self;
        executor.ensure_content_key()?;
        let FileRewrapExecutor {
            ctx,
            mut protected,
            content_key,
            ..
        } = executor;
        protected.updated_at = time::generate_current_timestamp()?;
        let signing = build_signing_context(ctx.key_ctx(), ctx.options().debug)?;
        let content_key = content_key.into_key();
        let mac_key = FileKeySchedule::extract(&content_key, &protected.sid)?.derive_mac_key()?;
        let signature = sign_file_document(
            &protected,
            &mac_key,
            signing.signing_key(),
            signing.signer_kid(),
            signing.signer_pub.clone(),
            ctx.options().debug,
        )?;

        let doc = FileEncDocument {
            protected,
            signature,
        };
        serde_json::to_string_pretty(&doc).map_err(|e| {
            Error::build_parse_error_with_source(
                format!("Failed to serialize file-enc v7: {}", e),
                e,
            )
        })
    }
}

impl<'a> FileRewrapExecutor<'a> {
    fn new(verified: VerifiedFileEncDocument, ctx: &'a RewrapContext<'a>) -> Self {
        let protected = verified.document().protected.clone();
        Self {
            ctx,
            protected,
            verified,
            content_key: FileContentKeyState::Unloaded,
        }
    }

    fn ensure_content_key(&mut self) -> Result<()> {
        if matches!(self.content_key, FileContentKeyState::Unloaded) {
            let content_key = unwrap_verified_file_content_key(
                &self.verified,
                self.ctx.member_handle(),
                self.ctx.key_ctx(),
                self.ctx.options().debug,
            )?;
            self.content_key = FileContentKeyState::Original(content_key);
        }
        Ok(())
    }
}

impl FileContentKeyState {
    fn as_ref(&self) -> &MasterKey {
        match self {
            Self::Original(content_key) | Self::Rotated(content_key) => content_key,
            Self::Unloaded => unreachable!("file content key must be loaded before use"),
        }
    }

    fn into_key(self) -> MasterKey {
        match self {
            Self::Original(content_key) | Self::Rotated(content_key) => content_key,
            Self::Unloaded => unreachable!("file content key must be loaded before finalization"),
        }
    }

    fn is_rotated(&self) -> bool {
        matches!(self, Self::Rotated(_))
    }
}

struct FileRewrapAdapter;

impl VerifiedRewrapDocument for VerifiedFileEncDocument {
    fn current_wrap_items(&self) -> &[WrapItem] {
        &self.document().protected.wrap
    }
}

impl RewrapDocumentAdapter for FileRewrapAdapter {
    type Content = FileEncContent;
    type Verified = VerifiedFileEncDocument;
    type Executor<'ctx> = FileRewrapExecutor<'ctx>;

    fn verify_content(content: &Self::Content, debug: bool) -> Result<Self::Verified> {
        verify_file_content(content, debug)
    }

    fn build_executor<'ctx>(
        verified: Self::Verified,
        ctx: &'ctx RewrapContext<'ctx>,
    ) -> Result<Self::Executor<'ctx>> {
        Ok(FileRewrapExecutor::new(verified, ctx))
    }
}

/// Rewrap file-enc v7 content.
pub fn rewrap_file_document(
    options: &RewrapOptions,
    content: &FileEncContent,
    member_handle: &str,
    key_ctx: &CryptoContext,
    target_members: &[VerifiedRecipientKey],
) -> Result<String> {
    rewrap_document_with_common_skeleton::<FileRewrapAdapter>(
        options,
        content,
        member_handle,
        key_ctx,
        target_members,
    )
}
