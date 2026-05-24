// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Feature-facing DTOs for reusable key generation results.
//! Excludes command orchestration result types owned by the app layer.

use crate::model::ssh::SshDeterminismStatus;
use std::path::PathBuf;

/// Result for key generation.
pub struct KeyGenerationResult {
    pub member_handle: String,
    pub kid: String,
    pub created_at: String,
    pub expires_at: String,
    pub keystore_root: PathBuf,
    pub key_dir: PathBuf,
    pub activated: bool,
    pub ssh_fingerprint: String,
    pub ssh_public_key: String,
    pub ssh_determinism: SshDeterminismStatus,
}
