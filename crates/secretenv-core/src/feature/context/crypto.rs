// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto context data.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

use crate::feature::context::expiry::VerifiedExpiresAt;
use crate::io::keystore::public_key_source::PublicKeySource;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::verified::VerifiedPrivateKey;

mod decryption_key;
mod loader;

pub use loader::{
    build_local_key_access, build_verified_private_key_from_password,
    load_crypto_context_from_keystore,
};
pub(crate) use loader::{build_signing_key, load_verified_private_key_from_keystore};

pub struct LocalKeyAccess {
    keystore_root: PathBuf,
    ssh_pubkey: String,
    ssh_backend: Box<dyn SignatureBackend>,
}

/// Context for cryptographic operations requiring member keys
pub struct CryptoContext {
    pub member_handle: MemberHandle,
    pub kid: Kid,
    pub pub_key_source: Box<dyn PublicKeySource>,
    pub workspace_path: Option<PathBuf>,
    pub private_key: VerifiedPrivateKey,
    pub signing_key: SigningKey,
    /// Key expiration timestamp (RFC 3339) from PrivateKeyProtected
    pub expires_at: VerifiedExpiresAt,
    selected_kid_override: Option<Kid>,
    local_key_access: Option<LocalKeyAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKeyInfo {
    pub kid: String,
    pub expires_at: String,
    pub used_fallback: bool,
}

pub struct DecryptionResult<T> {
    pub value: T,
    pub key_info: DecryptionKeyInfo,
}

pub(crate) struct PrivateKeyLoadResult {
    pub(crate) private_key: VerifiedPrivateKey,
    pub(crate) expires_at: VerifiedExpiresAt,
}

pub(crate) enum DecryptionKeyResolution<'a> {
    Active {
        private_key: &'a VerifiedPrivateKey,
        info: DecryptionKeyInfo,
    },
    Fallback {
        private_key: Box<VerifiedPrivateKey>,
        info: DecryptionKeyInfo,
    },
}

impl LocalKeyAccess {
    fn new(
        keystore_root: PathBuf,
        ssh_pubkey: String,
        ssh_backend: Box<dyn SignatureBackend>,
    ) -> Self {
        Self {
            keystore_root,
            ssh_pubkey,
            ssh_backend,
        }
    }
}

impl<'a> DecryptionKeyResolution<'a> {
    pub(crate) fn private_key(&self) -> &VerifiedPrivateKey {
        match self {
            Self::Active { private_key, .. } => private_key,
            Self::Fallback { private_key, .. } => private_key,
        }
    }

    pub(crate) fn info(&self) -> &DecryptionKeyInfo {
        match self {
            Self::Active { info, .. } => info,
            Self::Fallback { info, .. } => info,
        }
    }
}

impl CryptoContext {
    pub fn new(
        member_handle: MemberHandle,
        kid: Kid,
        pub_key_source: Box<dyn PublicKeySource>,
        workspace_path: Option<PathBuf>,
        private_key: VerifiedPrivateKey,
        signing_key: SigningKey,
        expires_at: VerifiedExpiresAt,
    ) -> Self {
        Self {
            member_handle,
            kid,
            pub_key_source,
            workspace_path,
            private_key,
            signing_key,
            expires_at,
            selected_kid_override: None,
            local_key_access: None,
        }
    }

    pub fn with_local_key_access(
        mut self,
        selected_kid_override: Option<Kid>,
        local_key_access: Option<LocalKeyAccess>,
    ) -> Self {
        self.selected_kid_override = selected_kid_override;
        self.local_key_access = local_key_access;
        self
    }

    pub(crate) fn local_keystore_root(&self) -> Option<&Path> {
        self.local_key_access
            .as_ref()
            .map(|access| access.keystore_root.as_path())
    }
}
