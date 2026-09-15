// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PublicKeySource trait and implementations for abstracting public key resolution.

use crate::io::keystore::access::KeystoreAccess;
use crate::io::workspace::members::{open_member_documents_at, MemberStatus};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::support::fs::anchor::AnchoredDir;
use crate::{Error, Result};

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
    workspace: AnchoredDir,
}

impl WorkspacePublicKeySource {
    pub(crate) fn new(workspace: AnchoredDir) -> Self {
        Self { workspace }
    }
}

impl PublicKeySource for WorkspacePublicKeySource {
    fn load_public_key(&self, member_handle: &MemberHandle) -> Result<PublicKey> {
        let name = format!("{member_handle}.json");
        for status in [MemberStatus::Active, MemberStatus::Incoming] {
            let documents = open_member_documents_at(&self.workspace, status)?;
            if documents.names().contains(&name) {
                if status != MemberStatus::Active {
                    return Err(Error::build_verification_error(
                        "member-status",
                        format!("Member '{member_handle}' is not active in workspace"),
                    ));
                }
                return Ok(documents.load_verified_document(&name)?.public_key);
            }
        }
        Err(Error::build_not_found_error(format!(
            "Member '{member_handle}' not found in workspace"
        )))
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
