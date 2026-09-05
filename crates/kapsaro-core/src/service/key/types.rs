// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Result types returned by the key service operations.
//! Keeps caller-facing result data separate from reusable feature key generation data.

use crate::feature::key::portable_export::PortableExportOutput;
use crate::model::public_key::PublicKey;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::secret::SecretString;

pub use crate::service::online::OnlineVerificationStatus;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingKeyDocument {
    PublicJson,
}

impl MissingKeyDocument {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicJson => "public.json",
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyInfo {
    Complete {
        kid: String,
        member_handle: String,
        /// Absent when the stored public key omits the optional `created_at`.
        created_at: Option<String>,
        expires_at: String,
        active: bool,
        format: String,
    },
    Incomplete {
        kid: String,
        member_handle: String,
        active: bool,
        missing_document: MissingKeyDocument,
    },
}

pub struct KeyListResult {
    pub entries: Vec<(String, Vec<KeyInfo>)>,
    pub total_keys: usize,
}

#[derive(Debug, Clone)]
pub struct KeyActivateResult {
    pub member_handle: String,
    pub kid: String,
    /// Key the stored local trust store signature names, when there is a store.
    /// A value other than `kid` means the store still depends on that key.
    pub trust_store_signer_kid: Option<String>,
    /// Why the stored local trust store could not be read, when it could not.
    pub trust_store_warning: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyRemoveResult {
    pub member_handle: String,
    pub kid: String,
    pub was_active: bool,
    /// Key that took over the local trust store signature before the removal.
    pub resigned_trust_store_kid: Option<String>,
    /// What the removal cost the local trust store, when it cost anything.
    pub trust_store_warning: Option<String>,
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
