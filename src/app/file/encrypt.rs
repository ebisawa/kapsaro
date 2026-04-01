// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::encrypt::encrypt_file_document;
use crate::feature::envelope::signature::{build_signing_context, SigningContext};
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::members::{list_active_member_ids, load_member_files};
use crate::support::fs::load_bytes;
use crate::{Error, Result};

/// Encrypt command inputs resolved at the application layer.
struct EncryptFileSession {
    execution: ExecutionContext,
    workspace_root: WorkspaceRoot,
    member_ids: Vec<String>,
    input_bytes: Vec<u8>,
}

impl EncryptFileSession {
    fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        input_path: &Path,
        ssh_ctx: Option<ResolvedSshSigner>,
    ) -> Result<Self> {
        let execution = ExecutionContext::resolve(options, member_id, None, ssh_ctx)?;
        enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
        let workspace_root = execution
            .workspace_root
            .clone()
            .ok_or_else(|| Error::Config {
                message: "Workspace is required for encrypt".to_string(),
            })?;
        let member_ids = list_active_member_ids(&workspace_root.root_path)?;
        let input_bytes = load_bytes(input_path)?;

        Ok(Self {
            execution,
            workspace_root,
            member_ids,
            input_bytes,
        })
    }

    fn verified_recipient_keys(
        &self,
        debug: bool,
    ) -> Result<Vec<crate::model::public_key::VerifiedRecipientKey>> {
        let public_keys = load_member_files(&self.workspace_root.root_path, &self.member_ids)?;
        verify_recipient_public_keys(&public_keys, debug)
    }

    fn signing_context<'a>(&'a self, debug: bool) -> Result<SigningContext<'a>> {
        build_signing_context(&self.execution.key_ctx, debug)
    }
}

pub fn encrypt_file_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    input_path: &Path,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<String> {
    let session = EncryptFileSession::load(options, member_id, input_path, ssh_ctx)?;
    let verified_keys = session.verified_recipient_keys(options.verbose)?;
    let signing = session.signing_context(options.verbose)?;
    encrypt_file_document(
        &session.input_bytes,
        &session.member_ids,
        &verified_keys,
        &signing,
    )
}
