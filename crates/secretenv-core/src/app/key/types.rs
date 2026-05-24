// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-facing DTOs for key commands.
//! Keeps CLI output data separate from reusable feature key generation data.

use crate::app::verification::OnlineVerificationStatus;
use crate::feature::key::portable_export::PortableExportOutput;
use crate::feature::key::types as feature_key_types;
use crate::model::public_key::PublicKey;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::secret::SecretString;

#[derive(Debug, Clone)]
pub struct KeyGenerationResult {
    pub member_handle: String,
    pub kid: String,
    pub expires_at: String,
    pub activated: bool,
    pub ssh_fingerprint: String,
    pub ssh_determinism: SshDeterminismStatus,
    pub github_verification: OnlineVerificationStatus,
}

impl From<feature_key_types::KeyGenerationResult> for KeyGenerationResult {
    fn from(r: feature_key_types::KeyGenerationResult) -> Self {
        Self {
            member_handle: r.member_handle,
            kid: r.kid,
            expires_at: r.expires_at,
            activated: r.activated,
            ssh_fingerprint: r.ssh_fingerprint,
            ssh_determinism: r.ssh_determinism,
            github_verification: OnlineVerificationStatus::NotConfigured,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub kid: String,
    pub member_handle: String,
    pub created_at: String,
    pub expires_at: String,
    pub active: bool,
    pub format: String,
}

pub struct KeyListResult {
    pub entries: Vec<(String, Vec<KeyInfo>)>,
    pub total_keys: usize,
}

pub struct KeyActivateResult {
    pub member_handle: String,
    pub kid: String,
}

pub struct KeyRemoveResult {
    pub member_handle: String,
    pub kid: String,
    pub was_active: bool,
}

pub struct KeyExportResult {
    pub member_handle: String,
    pub kid: String,
    pub public_key: PublicKey,
}

pub struct KeyExportPrivateResult {
    pub member_handle: String,
    pub kid: String,
    pub encoded_key: SecretString,
    pub password_warning: Option<String>,
}

impl From<PortableExportOutput> for KeyExportPrivateResult {
    fn from(output: PortableExportOutput) -> Self {
        Self {
            member_handle: output.member_handle,
            kid: output.kid,
            encoded_key: output.encoded_key,
            password_warning: output.password_warning,
        }
    }
}
