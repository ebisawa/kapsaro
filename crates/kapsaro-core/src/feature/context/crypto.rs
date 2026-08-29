// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto context data.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

use crate::feature::context::expiry::LocalKeyPairExpiry;
use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::io::keystore::access::KeystoreAccess;
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
pub use loader::build_verified_private_key_from_password;
pub(crate) use loader::{
    build_signing_key, load_crypto_context_from_keystore,
    load_crypto_context_from_keystore_with_selected_kid,
};
pub use signing::{build_signing_context, SigningContext, VerifiedSigningContext};

pub struct LocalKeyAccess {
    keystore_access: KeystoreAccess,
    ssh_pubkey: String,
    ssh_backend: Box<dyn SignatureBackend>,
}

/// Context for cryptographic operations requiring member keys
pub struct CryptoContext {
    member_handle: MemberHandle,
    kid: Kid,
    pub(crate) pub_key_source: Box<dyn PublicKeySource>,
    // Never read by crate code: it is surfaced only through `workspace_path()`,
    // which the `cli-test-support` test harness uses to locate the workspace.
    #[cfg_attr(not(feature = "cli-test-support"), allow(dead_code))]
    workspace_path: Option<PathBuf>,
    private_key: VerifiedPrivateKey,
    signing_key: SigningKey,
    local_key_identity: LocalKeyIdentity,
    local_key_expiry: LocalKeyPairExpiry,
    selected_kid_override: Option<Kid>,
    local_key_access: Option<LocalKeyAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalKeyIdentity {
    member_handle: MemberHandle,
    kid: Kid,
    sig_x: [u8; 32],
}

/// How a stored public key stands against the identity of a local key.
///
/// The mismatches are kept apart so callers that report them can say which of
/// the three parts disagreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicKeyMatch {
    Matches,
    MemberHandleMismatch,
    KidMismatch,
    SignaturePublicKeyMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKeyInfo {
    pub kid: String,
    pub expires_at: String,
    pub used_fallback: bool,
    pub(crate) key_identity: LocalKeyIdentity,
    pub(crate) key_expiry: LocalKeyPairExpiry,
}

pub struct DecryptionResult<T> {
    pub value: T,
    pub key_info: DecryptionKeyInfo,
}

pub(crate) struct PrivateKeyLoadResult {
    pub(crate) private_key: VerifiedPrivateKey,
    pub(crate) key_identity: LocalKeyIdentity,
    pub(crate) key_expiry: LocalKeyPairExpiry,
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
        keystore_access: KeystoreAccess,
        ssh_pubkey: String,
        ssh_backend: Box<dyn SignatureBackend>,
    ) -> Self {
        Self {
            keystore_access,
            ssh_pubkey,
            ssh_backend,
        }
    }
}

impl LocalKeyIdentity {
    pub(crate) fn new(member_handle: MemberHandle, kid: Kid, sig_x: [u8; 32]) -> Self {
        Self {
            member_handle,
            kid,
            sig_x,
        }
    }

    /// Compare a stored public key against this identity, naming what differs.
    ///
    /// The Ed25519 public key is compared in constant time; the member handle
    /// and key id are labels the document carries in the clear.
    pub(crate) fn check_public_key(&self, public_key: &PublicKey) -> Result<PublicKeyMatch> {
        if public_key.protected.subject_handle != self.member_handle.as_str() {
            return Ok(PublicKeyMatch::MemberHandleMismatch);
        }
        if public_key.protected.kid != self.kid.as_str() {
            return Ok(PublicKeyMatch::KidMismatch);
        }
        let public_sig_x: [u8; 32] =
            decode_base64url_nopad_array(&public_key.protected.keys.sig.x, "Ed25519 public key")?;
        if !bool::from(public_sig_x.as_slice().ct_eq(self.sig_x.as_slice())) {
            return Ok(PublicKeyMatch::SignaturePublicKeyMismatch);
        }
        Ok(PublicKeyMatch::Matches)
    }

    pub(crate) fn matches_public_key(&self, public_key: &PublicKey) -> Result<bool> {
        Ok(self.check_public_key(public_key)? == PublicKeyMatch::Matches)
    }

    pub(crate) fn from_public_key(public_key: &PublicKey) -> Result<Self> {
        let sig_x =
            decode_base64url_nopad_array(&public_key.protected.keys.sig.x, "Ed25519 public key")?;
        Ok(Self::new(
            MemberHandle::try_from(public_key.protected.subject_handle.clone())?,
            Kid::from_canonical(public_key.protected.kid.clone())?,
            sig_x,
        ))
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
    pub(crate) fn new(
        member_handle: MemberHandle,
        kid: Kid,
        pub_key_source: Box<dyn PublicKeySource>,
        workspace_path: Option<PathBuf>,
        private_key: VerifiedPrivateKey,
        signing_key: SigningKey,
        local_key_expiry: LocalKeyPairExpiry,
    ) -> Self {
        let local_key_identity = LocalKeyIdentity::new(
            member_handle.clone(),
            kid.clone(),
            derive_signing_public_key_x(&signing_key),
        );
        Self {
            member_handle,
            kid,
            pub_key_source,
            workspace_path,
            private_key,
            signing_key,
            local_key_identity,
            local_key_expiry,
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

    #[cfg_attr(not(feature = "cli-test-support"), allow(dead_code))]
    pub fn private_key(&self) -> &VerifiedPrivateKey {
        &self.private_key
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    #[cfg_attr(not(feature = "cli-test-support"), allow(dead_code))]
    pub fn workspace_path(&self) -> Option<&Path> {
        self.workspace_path.as_deref()
    }

    pub fn expires_at(&self) -> &str {
        self.local_key_expiry.primary_expires_at()
    }

    pub(crate) fn member_handle_id(&self) -> &MemberHandle {
        &self.member_handle
    }

    pub(crate) fn kid_id(&self) -> &Kid {
        &self.kid
    }

    pub(crate) fn self_signature_public_key_x(&self) -> [u8; 32] {
        self.local_key_identity.sig_x
    }

    pub(crate) fn local_key_identity(&self) -> &LocalKeyIdentity {
        &self.local_key_identity
    }

    pub(crate) fn enforce_signing_key_not_expired(&self) -> Result<()> {
        self.local_key_expiry.enforce_not_expired_for_signing()
    }

    pub(crate) fn build_signing_key_expiry_warning(&self) -> Result<Option<String>> {
        self.local_key_expiry.build_signing_warning()
    }

    pub(crate) fn local_keystore_access(&self) -> Option<&KeystoreAccess> {
        self.local_key_access
            .as_ref()
            .map(|access| &access.keystore_access)
    }
}

fn derive_signing_public_key_x(signing_key: &SigningKey) -> [u8; 32] {
    let verifying_key: ed25519_dalek::VerifyingKey = signing_key.into();
    verifying_key.to_bytes()
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_crypto_validation_test.rs"]
mod feature_context_crypto_validation_test;
