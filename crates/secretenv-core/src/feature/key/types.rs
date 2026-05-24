// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Feature-facing DTOs for reusable key document generation.
//! Keeps keystore persistence and activation orchestration in the app layer.

use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::model::ssh::SshDeterminismStatus;

/// Generated key documents and metadata before persistence.
pub struct KeyGenerationResult {
    pub member_handle: String,
    pub kid: String,
    pub created_at: String,
    pub expires_at: String,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub ssh_fingerprint: String,
    pub ssh_public_key: String,
    pub ssh_determinism: SshDeterminismStatus,
}
