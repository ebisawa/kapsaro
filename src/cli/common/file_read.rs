// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI adapter for one trust-authorized file read.
//! Resolves command inputs before opening the public workspace read session.

use std::io;
use std::path::PathBuf;

use crate::cli::common::command::ReadCommandLabels;
use crate::cli::common::context::CliContext;
use crate::cli::common::key_context::load_read_key_context;
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::presentation::tty;
use crate::cli::common::read_review::{
    accept_non_member, approve_next_key, print_unresolved_recipients,
};
use crate::cli::common::trust::run_with_workspace_read_trust_store_reset_recovery;
use crate::cli::options::ToCommonOptions;
use kapsaro_core::api::config::LocalStateSession;
use kapsaro_core::api::file::{FileReadOperation, TrustedFileEncArtifact};
use kapsaro_core::api::key::KeyContext;
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::secret::SecretBytes;
use kapsaro_core::api::trust::{
    AuthorizedRead, FileReadTarget, KnownKeyReview, ReadSessionDecision, WorkspaceReadSession,
};
use kapsaro_core::{Error, Result};
use tracing::debug;

/// Resolved CLI inputs retained for one file read command.
pub(crate) struct FileReadSession {
    workspace_path: PathBuf,
    local_state: Option<LocalStateSession>,
    key_ctx: KeyContext,
    options: OperationOptions,
    allow_non_member: bool,
    known_key_review: KnownKeyReview,
}

impl FileReadSession {
    pub(crate) fn open(
        common: &impl ToCommonOptions,
        allow_expired_key: bool,
        allow_non_member: bool,
        member_handle: Option<String>,
        kid: Option<&str>,
    ) -> Result<Self> {
        let common = common.to_common_options();
        let context = CliContext::resolve(&common)?;
        let workspace_path = context.workspace_path()?;
        let options = OperationOptions::new()
            .with_allow_expired_key(context.allow_expired_key(allow_expired_key)?);
        let allow_non_member = context.allow_non_member(allow_non_member)?;
        let known_key_review = if context.strict_key_checking() {
            KnownKeyReview::Required
        } else {
            KnownKeyReview::Skipped
        };
        let key_ctx =
            load_read_key_context(&context, &common, &workspace_path, member_handle, kid)?;
        let local_state = context.into_optional_local_state()?;
        Ok(Self {
            workspace_path,
            local_state,
            key_ctx,
            options,
            allow_non_member,
            known_key_review,
        })
    }

    pub(crate) fn decrypt(
        &self,
        input_path: Option<&PathBuf>,
        from_stdin: bool,
    ) -> Result<SecretBytes> {
        let session = self.open_workspace_session()?;
        let target = load_decrypt_target(&session, input_path, from_stdin)?;
        let labels = ReadCommandLabels {
            context: "decrypt signer",
            allow_non_member: self.allow_non_member,
        };
        run_with_workspace_read_trust_store_reset_recovery(&session, || {
            debug!(
                "[TRUST] read gate: operation=decrypt, allow_non_member={}",
                labels.allow_non_member
            );
            let decision = session.begin_file_read(
                &target,
                FileReadOperation::Decrypt,
                labels.allow_non_member && tty::is_interactive(),
            )?;
            authorize_file_decision(&session, decision, labels)?
                .into_value()
                .decrypt_bytes()
        })
    }

    fn open_workspace_session(&self) -> Result<WorkspaceReadSession<'_>> {
        WorkspaceReadSession::open_with_local_state(
            &self.workspace_path,
            self.local_state.as_ref(),
            &self.key_ctx,
            self.options,
        )
        .map(|session| session.with_known_key_review(self.known_key_review))
    }
}

fn authorize_file_decision<'a>(
    session: &WorkspaceReadSession<'a>,
    mut decision: ReadSessionDecision<TrustedFileEncArtifact<'a>>,
    labels: ReadCommandLabels<'_>,
) -> Result<AuthorizedRead<TrustedFileEncArtifact<'a>>> {
    loop {
        match decision {
            ReadSessionDecision::Authorized(authorized) => {
                print_unresolved_recipients(authorized.unresolved_recipient_kids());
                print_warnings(authorized.value().warnings());
                return Ok(authorized);
            }
            ReadSessionDecision::ReviewRequired(mut review) => {
                let acceptance = if review.non_member_signer().is_some() {
                    Some(accept_non_member(&mut review)?)
                } else {
                    if !approve_next_key(session, &review, labels.context)? {
                        return Err(build_target_changed_error());
                    }
                    None
                };
                decision = session.resume_file_read(review, acceptance)?;
            }
        }
    }
}

fn load_decrypt_target(
    session: &WorkspaceReadSession<'_>,
    input_path: Option<&PathBuf>,
    from_stdin: bool,
) -> Result<FileReadTarget> {
    if from_stdin {
        return session.capture_file_read_target(io::stdin().lock(), "stdin");
    }
    input_path
        .map(|path| session.open_file_read_target(path))
        .transpose()?
        .ok_or_else(|| {
            Error::build_invalid_argument_error("INPUT is required unless --stdin is used")
        })
}

fn build_target_changed_error() -> Error {
    Error::build_verification_error(
        "E_TRUST_TARGET_CHANGED",
        "Trust state changed while reviewing the file artifact",
    )
}
