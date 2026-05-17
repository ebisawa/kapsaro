// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PublicKeySource trait and implementations for abstracting public key resolution.

use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::public_keys::load_public_keys_for_member_handles;
use crate::io::keystore::storage::load_public_key;
use crate::io::workspace::members::load_member_file;
use crate::model::public_key::PublicKey;
use crate::Result;
use std::path::{Path, PathBuf};

/// Abstraction for loading public keys from different sources.
pub trait PublicKeySource: Send + Sync {
    /// Load a single public key by member handle.
    fn load_public_key(&self, member_handle: &str) -> Result<PublicKey>;

    /// Load public keys for multiple member handles.
    fn load_public_keys_for_member_handles(
        &self,
        member_handles: &[String],
    ) -> Result<Vec<PublicKey>>;
}

/// Loads public keys from the local keystore directory.
pub struct KeystorePublicKeySource {
    keystore_root: PathBuf,
}

impl KeystorePublicKeySource {
    pub fn new(keystore_root: PathBuf) -> Self {
        Self { keystore_root }
    }

    pub fn keystore_root(&self) -> &Path {
        &self.keystore_root
    }
}

impl PublicKeySource for KeystorePublicKeySource {
    fn load_public_key(&self, member_handle: &str) -> Result<PublicKey> {
        let kid = resolve_kid(&self.keystore_root, member_handle, None)?;
        load_public_key(&self.keystore_root, member_handle, &kid)
    }

    fn load_public_keys_for_member_handles(
        &self,
        member_handles: &[String],
    ) -> Result<Vec<PublicKey>> {
        load_public_keys_for_member_handles(&self.keystore_root, member_handles)
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
    fn load_public_key(&self, member_handle: &str) -> Result<PublicKey> {
        let (public_key, status) = load_member_file(&self.workspace_path, member_handle)?;
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
        member_handles: &[String],
    ) -> Result<Vec<PublicKey>> {
        member_handles
            .iter()
            .map(|id| self.load_public_key(id))
            .collect()
    }
}
