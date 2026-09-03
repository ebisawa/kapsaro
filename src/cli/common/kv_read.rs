// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared service-session read pipeline for KV query commands.
//! Owns CLI review prompts while service capabilities own authorization state.

use std::path::{Path, PathBuf};

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
use kapsaro_core::api::key::KeyContext;
use kapsaro_core::api::kv::{resolve_kv_store_file_name, KvReadOperation, TrustedKvEncArtifact};
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::trust::{
    AuthorizedRead, KnownKeyReview, ReadSessionDecision, WorkspaceReadSession,
};
use kapsaro_core::{Error, Result};
use tracing::debug;

/// One KV target and identity resolved once for a CLI command.
pub(crate) struct KvReadSession {
    workspace_path: PathBuf,
    local_state: Option<LocalStateSession>,
    key_ctx: KeyContext,
    options: OperationOptions,
    allow_non_member: bool,
    known_key_review: KnownKeyReview,
    artifact_path: PathBuf,
    artifact_file_name: String,
}

/// Whether a KV command supports resolving the non-member review setting.
pub(crate) enum NonMemberReviewMode {
    Disabled,
    Configured(bool),
}

impl KvReadSession {
    pub(crate) fn open(
        common: &impl ToCommonOptions,
        allow_expired_key: bool,
        non_member_review: NonMemberReviewMode,
        store_name: Option<&str>,
        member_handle: Option<String>,
    ) -> Result<Self> {
        let common = common.to_common_options();
        let context = CliContext::resolve(&common)?;
        let workspace_path = context.workspace_path()?;
        let options = OperationOptions::new()
            .with_allow_expired_key(context.allow_expired_key(allow_expired_key)?);
        let allow_non_member = match non_member_review {
            NonMemberReviewMode::Disabled => false,
            NonMemberReviewMode::Configured(cli_value) => context.allow_non_member(cli_value)?,
        };
        let known_key_review = if context.strict_key_checking() {
            KnownKeyReview::Required
        } else {
            KnownKeyReview::Skipped
        };
        let key_ctx =
            load_read_key_context(&context, &common, &workspace_path, member_handle, None)?;
        let artifact_file_name = resolve_kv_store_file_name(store_name)?;
        let artifact_path = workspace_path.join("secrets").join(&artifact_file_name);
        let local_state = context.into_optional_local_state()?;
        Ok(Self {
            workspace_path,
            local_state,
            key_ctx,
            options,
            allow_non_member,
            known_key_review,
            artifact_path,
            artifact_file_name,
        })
    }

    pub(crate) fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    pub(crate) fn allow_non_member(&self) -> bool {
        self.allow_non_member
    }

    pub(crate) fn authorize(
        &self,
        operation: KvReadOperation,
        labels: ReadCommandLabels<'_>,
    ) -> Result<AuthorizedRead<TrustedKvEncArtifact<'_>>> {
        let session = self.open_workspace_session()?;
        run_with_workspace_read_trust_store_reset_recovery(&session, || {
            debug!(
                "[TRUST] read gate: operation={operation:?}, allow_non_member={}",
                labels.allow_non_member
            );
            let decision = session.begin_kv_read(
                &self.artifact_file_name,
                operation.clone(),
                labels.allow_non_member && tty::is_interactive(),
            )?;
            authorize_kv_decision(&session, decision, labels)
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

fn authorize_kv_decision<'a>(
    session: &WorkspaceReadSession<'a>,
    mut decision: ReadSessionDecision<TrustedKvEncArtifact<'a>>,
    labels: ReadCommandLabels<'_>,
) -> Result<AuthorizedRead<TrustedKvEncArtifact<'a>>> {
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
                decision = session.resume_kv_read(review, acceptance)?;
            }
        }
    }
}

fn build_target_changed_error() -> Error {
    Error::build_verification_error(
        "E_TRUST_TARGET_CHANGED",
        "Trust state changed while reviewing the KV artifact",
    )
}
