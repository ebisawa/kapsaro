// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::types::SshSigner;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::ssh::SshDeterminismStatus;
use std::path::PathBuf;

/// Input parameters for SSH signing context resolution.
pub(crate) struct SshSigningParams {
    pub ssh_key: Option<PathBuf>,
    pub signing_method: Option<SshSigner>,
    pub base_dir: Option<PathBuf>,
    pub verbose: bool,
    pub check_determinism: bool,
}

/// Resolved SSH signing context.
pub(crate) struct SshSigningContext {
    pub public_key: String,
    pub fingerprint: String,
    pub backend: Box<dyn SignatureBackend>,
    pub determinism: SshDeterminismStatus,
}

pub(crate) struct ResolvedSshCommands {
    pub ssh_keygen_path: String,
    pub ssh_add_path: String,
}
