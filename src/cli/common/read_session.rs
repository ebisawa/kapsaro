// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI inputs and review loop for trust-gated read sessions.
//! Resolves command inputs once, then drives service reviews until a read is authorized.

use std::path::{Path, PathBuf};

use crate::cli::common::command::ReadCommandLabels;
use crate::cli::common::context::CliContext;
use crate::cli::common::key_context::load_read_key_context;
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::read_review::{
    accept_non_member, approve_next_key, print_unresolved_recipients,
};
use crate::cli::options::ToCommonOptions;
use kapsaro_core::api::config::LocalStateSession;
use kapsaro_core::api::file::TrustedFileEncArtifact;
use kapsaro_core::api::key::KeyContext;
use kapsaro_core::api::kv::TrustedKvEncArtifact;
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::trust::{
    AuthorizedRead, KnownKeyReview, ReadAcceptance, ReadReview, ReadSessionDecision,
    WorkspaceReadSession,
};
use kapsaro_core::{Error, Result};

/// Inputs a read command resolves once before it opens a workspace read session.
pub(crate) struct ReadSessionInputs {
    workspace_path: PathBuf,
    local_state: Option<LocalStateSession>,
    key_ctx: KeyContext,
    options: OperationOptions,
    allow_non_member: bool,
    known_key_review: KnownKeyReview,
}

impl ReadSessionInputs {
    /// Resolve the inputs shared by every read command.
    ///
    /// The non-member setting is selected through a callback because commands
    /// differ on whether the option exists at all, while the surrounding
    /// resolution order stays fixed for every command.
    pub(crate) fn resolve<Select>(
        common: &impl ToCommonOptions,
        allow_expired_key: bool,
        member_handle: Option<String>,
        kid: Option<&str>,
        select_allow_non_member: Select,
    ) -> Result<Self>
    where
        Select: FnOnce(&CliContext) -> Result<bool>,
    {
        let context = CliContext::resolve(common)?;
        let workspace_path = context.workspace_path()?;
        let options = OperationOptions::new()
            .with_allow_expired_key(context.allow_expired_key(allow_expired_key)?);
        let allow_non_member = select_allow_non_member(&context)?;
        let known_key_review = if context.strict_key_checking()?.is_disabled() {
            KnownKeyReview::Skipped
        } else {
            KnownKeyReview::Required
        };
        let key_ctx = load_read_key_context(&context, &workspace_path, member_handle, kid)?;
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

    pub(crate) fn workspace_path(&self) -> &Path {
        &self.workspace_path
    }

    pub(crate) fn allow_non_member(&self) -> bool {
        self.allow_non_member
    }

    pub(crate) fn open_workspace_session(&self) -> Result<WorkspaceReadSession<'_>> {
        WorkspaceReadSession::open_with_local_state(
            &self.workspace_path,
            self.local_state.as_ref(),
            &self.key_ctx,
            self.options,
        )
        .map(|session| session.with_known_key_review(self.known_key_review))
    }
}

/// Which artifact a read review is bound to, for review-failure messages.
#[derive(Clone, Copy)]
pub(crate) enum ReadArtifactKind {
    File,
    Kv,
}

impl ReadArtifactKind {
    fn label(self) -> &'static str {
        match self {
            Self::File => "file artifact",
            Self::Kv => "KV artifact",
        }
    }
}

/// Warnings a trust-authorized read artifact carries for CLI display.
pub(crate) trait ReadArtifactWarnings {
    fn warnings(&self) -> &[String];
}

impl ReadArtifactWarnings for TrustedFileEncArtifact<'_> {
    fn warnings(&self) -> &[String] {
        TrustedFileEncArtifact::warnings(self)
    }
}

impl ReadArtifactWarnings for TrustedKvEncArtifact<'_> {
    fn warnings(&self) -> &[String] {
        TrustedKvEncArtifact::warnings(self)
    }
}

/// Answer every review the session raises until it grants the read.
///
/// The resume callback carries the artifact-specific service operation, so the
/// file and KV read paths share one review loop.
pub(crate) fn authorize_read_decision<T, Resume>(
    session: &WorkspaceReadSession<'_>,
    mut decision: ReadSessionDecision<T>,
    labels: ReadCommandLabels<'_>,
    kind: ReadArtifactKind,
    resume: Resume,
) -> Result<AuthorizedRead<T>>
where
    T: ReadArtifactWarnings,
    Resume: Fn(Box<ReadReview>, Option<ReadAcceptance>) -> Result<ReadSessionDecision<T>>,
{
    loop {
        match decision {
            ReadSessionDecision::Authorized(authorized) => {
                print_unresolved_recipients(authorized.unresolved_recipient_kids());
                print_warnings(authorized.value().warnings());
                return Ok(authorized);
            }
            ReadSessionDecision::ReviewRequired(mut review) => {
                let acceptance = review_pending_request(session, &mut review, labels, kind)?;
                decision = resume(review, acceptance)?;
            }
        }
    }
}

/// Resolve the single review the session is waiting on, in place.
fn review_pending_request(
    session: &WorkspaceReadSession<'_>,
    review: &mut ReadReview,
    labels: ReadCommandLabels<'_>,
    kind: ReadArtifactKind,
) -> Result<Option<ReadAcceptance>> {
    if review.non_member_signer().is_some() {
        return accept_non_member(review).map(Some);
    }
    if !approve_next_key(session, review, labels.context)? {
        return Err(build_target_changed_error(kind));
    }
    Ok(None)
}

fn build_target_changed_error(kind: ReadArtifactKind) -> Error {
    Error::build_verification_error(
        "E_TRUST_TARGET_CHANGED",
        format!("Trust state changed while reviewing the {}", kind.label()),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_read_session_test.rs"]
mod cli_common_read_session_test;
