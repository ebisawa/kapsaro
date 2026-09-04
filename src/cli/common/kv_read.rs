// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared service-session read pipeline for KV query commands.
//! Owns CLI review prompts while service capabilities own authorization state.

use std::path::{Path, PathBuf};

use crate::cli::common::command::ReadCommandLabels;
use crate::cli::common::presentation::tty;
use crate::cli::common::read_session::{
    authorize_read_decision, ReadArtifactKind, ReadSessionInputs,
};
use crate::cli::common::trust::run_with_workspace_read_trust_store_reset_recovery;
use crate::cli::options::ToCommonOptions;
use kapsaro_core::api::kv::{resolve_kv_store_file_name, KvReadOperation, TrustedKvEncArtifact};
use kapsaro_core::api::trust::AuthorizedRead;
use kapsaro_core::api::workspace::SECRETS_DIR_NAME;
use kapsaro_core::Result;
use tracing::debug;

/// One KV target and identity resolved once for a CLI command.
pub(crate) struct KvReadSession {
    inputs: ReadSessionInputs,
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
        let inputs = ReadSessionInputs::resolve(
            common,
            allow_expired_key,
            member_handle,
            None,
            |context| match non_member_review {
                NonMemberReviewMode::Disabled => Ok(false),
                NonMemberReviewMode::Configured(cli_value) => context.allow_non_member(cli_value),
            },
        )?;
        let artifact_file_name = resolve_kv_store_file_name(store_name)?;
        let artifact_path = inputs
            .workspace_path()
            .join(SECRETS_DIR_NAME)
            .join(&artifact_file_name);
        Ok(Self {
            inputs,
            artifact_path,
            artifact_file_name,
        })
    }

    pub(crate) fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    pub(crate) fn allow_non_member(&self) -> bool {
        self.inputs.allow_non_member()
    }

    pub(crate) fn authorize(
        &self,
        operation: KvReadOperation,
        labels: ReadCommandLabels<'_>,
    ) -> Result<AuthorizedRead<TrustedKvEncArtifact<'_>>> {
        let session = self.inputs.open_workspace_session()?;
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
            authorize_read_decision(
                &session,
                decision,
                labels,
                ReadArtifactKind::Kv,
                |review, acceptance| session.resume_kv_read(review, acceptance),
            )
        })
    }
}
