// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto context data.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

use crate::feature::context::expiry::{
    build_signing_key_expiry_warning, enforce_key_not_expired_for_signing, VerifiedExpiresAt,
};
use crate::io::keystore::public_key_source::PublicKeySource;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::verified::VerifiedPrivateKey;
use crate::Result;

mod decryption_key;
mod kem;
mod loader;
mod signing;

pub use kem::decode_kem_secret_key;
pub use loader::{
    build_local_key_access, build_verified_private_key_from_password,
    load_crypto_context_from_keystore,
};
pub(crate) use loader::{build_signing_key, load_verified_private_key_from_keystore};
pub use signing::{build_signing_context, SigningContext, VerifiedSigningContext};

pub struct LocalKeyAccess {
    keystore_root: PathBuf,
    ssh_pubkey: String,
    ssh_backend: Box<dyn SignatureBackend>,
}

/// Context for cryptographic operations requiring member keys
pub struct CryptoContext {
    member_handle: MemberHandle,
    kid: Kid,
    pub(crate) pub_key_source: Box<dyn PublicKeySource>,
    workspace_path: Option<PathBuf>,
    private_key: VerifiedPrivateKey,
    signing_key: SigningKey,
    /// Key expiration timestamp (RFC 3339) from PrivateKeyProtected
    expires_at: VerifiedExpiresAt,
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

    pub fn member_handle(&self) -> &str {
        self.member_handle.as_str()
    }

    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }

    pub fn private_key(&self) -> &VerifiedPrivateKey {
        &self.private_key
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn workspace_path(&self) -> Option<&Path> {
        self.workspace_path.as_deref()
    }

    pub fn expires_at(&self) -> &str {
        self.expires_at.as_str()
    }

    pub fn load_signer_public_key(&self) -> Result<PublicKey> {
        self.pub_key_source.load_public_key(self.member_handle())
    }

    pub(crate) fn member_handle_id(&self) -> &MemberHandle {
        &self.member_handle
    }

    pub(crate) fn self_signature_public_key_x(&self) -> [u8; 32] {
        let verifying_key: ed25519_dalek::VerifyingKey = (&self.signing_key).into();
        verifying_key.to_bytes()
    }

    pub(crate) fn enforce_signing_key_not_expired(&self) -> Result<()> {
        enforce_key_not_expired_for_signing(&self.expires_at)
    }

    pub(crate) fn build_signing_key_expiry_warning(&self) -> Result<Option<String>> {
        build_signing_key_expiry_warning(&self.expires_at)
    }

    pub(crate) fn local_keystore_root(&self) -> Option<&Path> {
        self.local_key_access
            .as_ref()
            .map(|access| access.keystore_root.as_path())
    }
}
