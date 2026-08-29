// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PublicKeySource trait and implementations for abstracting public key resolution.

use crate::io::keystore::access::KeystoreAccess;
use crate::io::workspace::members::load_member_file;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::{Error, Result};
use std::path::PathBuf;

/// Abstraction for loading public keys from different sources.
pub trait PublicKeySource: Send + Sync {
    /// Load a single public key by member handle.
    fn load_public_key(&self, member_handle: &MemberHandle) -> Result<PublicKey>;

    /// Load the public key a member holds under one named key id.
    ///
    /// The default answers from the single key the source keeps per member and
    /// refuses it when it is not the key that was asked for, which is what a
    /// source holding one key per member can honestly say. A source that keeps
    /// several keys per member overrides this to read the named one.
    fn load_public_key_for_kid(
        &self,
        member_handle: &MemberHandle,
        kid: &Kid,
    ) -> Result<PublicKey> {
        let public_key = self.load_public_key(member_handle)?;
        ensure_public_key_has_kid(&public_key, kid)?;
        Ok(public_key)
    }

    /// Load public keys for multiple member handles.
    fn load_public_keys_for_member_handles(
        &self,
        member_handles: &[MemberHandle],
    ) -> Result<Vec<PublicKey>>;
}

/// Loads public keys from the local keystore directory.
pub struct KeystorePublicKeySource {
    keystore_access: KeystoreAccess,
}

impl KeystorePublicKeySource {
    pub(crate) fn new(keystore_access: KeystoreAccess) -> Self {
        Self { keystore_access }
    }
}

impl PublicKeySource for KeystorePublicKeySource {
    fn load_public_key(&self, member_handle: &MemberHandle) -> Result<PublicKey> {
        self.keystore_access
            .resolve_public_key(member_handle, None)
            .map(|(_, public_key)| public_key)
    }

    fn load_public_key_for_kid(
        &self,
        member_handle: &MemberHandle,
        kid: &Kid,
    ) -> Result<PublicKey> {
        self.keystore_access.load_public_key(member_handle, kid)
    }

    fn load_public_keys_for_member_handles(
        &self,
        member_handles: &[MemberHandle],
    ) -> Result<Vec<PublicKey>> {
        member_handles
            .iter()
            .map(|member_handle| self.load_public_key(member_handle))
            .collect()
    }
}

/// Loads public keys from workspace member files (members/active/).
pub struct WorkspacePublicKeySource {
    workspace_path: PathBuf,
}

impl WorkspacePublicKeySource {
    pub fn new(workspace_path: PathBuf) -> Self {
        Self { workspace_path }
    }
}

impl PublicKeySource for WorkspacePublicKeySource {
    fn load_public_key(&self, member_handle: &MemberHandle) -> Result<PublicKey> {
        let (public_key, status) = load_member_file(&self.workspace_path, member_handle.as_str())?;
        if status != crate::io::workspace::members::MemberStatus::Active {
            return Err(crate::Error::build_verification_error(
                "member-status".to_string(),
                format!("Member '{}' is not active in workspace", member_handle),
            ));
        }
        Ok(public_key)
    }

    fn load_public_keys_for_member_handles(
        &self,
        member_handles: &[MemberHandle],
    ) -> Result<Vec<PublicKey>> {
        member_handles
            .iter()
            .map(|id| self.load_public_key(id))
            .collect()
    }
}

/// Refuse a public key that is not the key that was asked for.
fn ensure_public_key_has_kid(public_key: &PublicKey, kid: &Kid) -> Result<()> {
    if public_key.protected.kid == kid.as_str() {
        return Ok(());
    }
    Err(Error::build_verification_error(
        "public-key-kid".to_string(),
        format!(
            "Public key of '{}' names key '{}' where key '{}' was asked for",
            public_key.protected.subject_handle, public_key.protected.kid, kid
        ),
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_public_key_source_test.rs"]
mod io_keystore_public_key_source_test;
