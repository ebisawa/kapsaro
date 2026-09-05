// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI adapter for one trust-authorized file read.
//! Resolves command inputs before opening the public workspace read session.

use std::io;
use std::path::PathBuf;

use crate::cli::common::command::ReadCommandLabels;
use crate::cli::common::presentation::tty;
use crate::cli::common::read_session::{
    authorize_read_decision, ReadArtifactKind, ReadSessionInputs,
};
use crate::cli::common::trust::run_with_workspace_read_trust_store_reset_recovery;
use crate::cli::options::ToCommonOptions;
use kapsaro_core::api::file::FileReadOperation;
use kapsaro_core::api::secret::SecretBytes;
use kapsaro_core::api::trust::{FileReadTarget, WorkspaceReadSession};
use kapsaro_core::{Error, Result};
use tracing::debug;

/// Resolved CLI inputs retained for one file read command.
pub(crate) struct FileReadSession {
    inputs: ReadSessionInputs,
}

impl FileReadSession {
    pub(crate) fn open(
        common: &impl ToCommonOptions,
        allow_expired_key: bool,
        allow_non_member: bool,
        member_handle: Option<String>,
        kid: Option<&str>,
    ) -> Result<Self> {
        let inputs =
            ReadSessionInputs::resolve(common, allow_expired_key, member_handle, kid, |context| {
                context.allow_non_member(allow_non_member)
            })?;
        Ok(Self { inputs })
    }

    pub(crate) fn decrypt(
        &self,
        input_path: Option<&PathBuf>,
        from_stdin: bool,
    ) -> Result<SecretBytes> {
        let session = self.inputs.open_workspace_session()?;
        let target = load_decrypt_target(&session, input_path, from_stdin)?;
        let labels = ReadCommandLabels {
            context: "decrypt signer",
            allow_non_member: self.inputs.allow_non_member(),
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
            authorize_read_decision(
                &session,
                decision,
                labels,
                ReadArtifactKind::File,
                |review, acceptance| session.resume_file_read(review, acceptance),
            )?
            .into_value()
            .decrypt_bytes()
        })
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
