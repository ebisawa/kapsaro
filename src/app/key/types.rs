// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::verification::OnlineVerificationStatus;
use crate::feature::key::portable_export::PortableExportOutput;
use crate::feature::key::types as feature_key_types;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::secret::SecretString;

#[derive(Debug, Clone)]
pub struct KeyGenerationResult {
    pub member_id: String,
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
            member_id: r.member_id,
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
    pub member_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub active: bool,
    pub format: String,
}

impl From<feature_key_types::KeyInfo> for KeyInfo {
    fn from(value: feature_key_types::KeyInfo) -> Self {
        Self {
            kid: value.kid,
            member_id: value.member_id,
            created_at: value.created_at,
            expires_at: value.expires_at,
            active: value.active,
            format: value.format,
        }
    }
}

pub struct KeyListResult {
    pub entries: Vec<(String, Vec<KeyInfo>)>,
    pub total_keys: usize,
}

impl From<feature_key_types::KeyListResult> for KeyListResult {
    fn from(value: feature_key_types::KeyListResult) -> Self {
        Self {
            entries: value
                .entries
                .into_iter()
                .map(|(member_id, keys)| (member_id, keys.into_iter().map(Into::into).collect()))
                .collect(),
            total_keys: value.total_keys,
        }
    }
}

pub struct KeyExportPrivateResult {
    pub member_id: String,
    pub kid: String,
    pub encoded_key: SecretString,
}

impl From<PortableExportOutput> for KeyExportPrivateResult {
    fn from(output: PortableExportOutput) -> Self {
        Self {
            member_id: output.member_id,
            kid: output.kid,
            encoded_key: output.encoded_key,
        }
    }
}
