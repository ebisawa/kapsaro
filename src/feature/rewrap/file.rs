// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap operations for file-enc v3 format.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::signature::sign_file_document;
use crate::feature::recipient::collect_target_recipient_ids;
use crate::feature::rewrap::file_op::recipients::{add_file_recipients, remove_file_recipients};
use crate::feature::rewrap::file_op::rotate::rotate_file_key;
use crate::feature::verify::file::verify_file_content;
use crate::format::content::FileEncContent;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::file_enc::{FileEncDocument, FileEncDocumentProtected};
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::time;
use crate::{Error, Result};
use std::path::Path;

use super::{execute_rewrap_operations, RewrapContext, RewrapExecutor, RewrapOptions};

/// Executor for file-enc rewrap operations.
struct FileRewrapExecutor<'a> {
    ctx: &'a RewrapContext<'a>,
    protected: FileEncDocumentProtected,
    verified: VerifiedFileEncDocument,
}

impl<'a> RewrapExecutor for FileRewrapExecutor<'a> {
    fn current_recipients(&self) -> Vec<String> {
        self.protected.wrap.iter().map(|w| w.rid.clone()).collect()
    }

    fn add_recipients(&mut self, recipients: &[String]) -> Result<()> {
        add_file_recipients(
            &mut self.protected,
            &self.verified,
            recipients,
            self.ctx.key_ctx(),
            self.ctx.target_members(),
            self.ctx.options().debug,
        )
    }

    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()> {
        remove_file_recipients(&mut self.protected, recipients)
    }

    fn rotate_key(&mut self) -> Result<()> {
        rotate_file_key(
            &mut self.protected,
            &self.verified,
            self.ctx.key_ctx(),
            self.ctx.target_members(),
            self.ctx.options().debug,
        )
    }

    fn clear_disclosure_history(&mut self) -> Result<()> {
        self.protected.removed_recipients = None;
        Ok(())
    }

    fn finalize(self) -> Result<String> {
        let mut protected = self.protected;
        protected.updated_at = time::current_timestamp()?;
        let signer_pub = self.ctx.load_signer_pub()?;
        let signature = sign_file_document(
            &protected,
            &self.ctx.key_ctx().signing_key,
            &self.ctx.key_ctx().kid,
            signer_pub,
            self.ctx.options().debug,
        )?;

        let doc = FileEncDocument {
            protected,
            signature,
        };
        serde_json::to_string_pretty(&doc).map_err(|e| Error::Parse {
            message: format!("Failed to serialize file-enc v3: {}", e),
            source: Some(Box::new(e)),
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
        }
    }
}

/// Rewrap file-enc v3 content.
pub fn rewrap_file_document(
    options: &RewrapOptions,
    content: &FileEncContent,
    member_id: &str,
    key_ctx: &CryptoContext,
    workspace_root: Option<&Path>,
    target_members: Option<&[VerifiedRecipientKey]>,
) -> Result<String> {
    let all_members = collect_target_recipient_ids(workspace_root, target_members)?;

    let verified = verify_file_content(content, options.debug)?;

    let ctx = RewrapContext::new(options, member_id, key_ctx, target_members);
    let executor = FileRewrapExecutor::new(verified, &ctx);
    execute_rewrap_operations(executor, options, &all_members)
}
