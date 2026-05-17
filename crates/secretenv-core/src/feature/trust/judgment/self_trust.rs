// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::keystore::paths::get_public_key_file_path_from_root;
use crate::io::keystore::storage::load_public_key;
use crate::model::identity::MemberHandle;
use crate::model::public_key::PublicKey;
use crate::Result;
use std::path::PathBuf;

use super::identity::{IntoMemberHandle, TrustIdentity};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelfTrustSet {
    member_handle: Option<MemberHandle>,
    sig_xs: Vec<[u8; 32]>,
    keystore_root: Option<PathBuf>,
}

impl SelfTrustSet {
    pub fn new<M, I>(member_handle: M, sig_xs: I) -> Self
    where
        M: IntoMemberHandle,
        I: IntoIterator<Item = [u8; 32]>,
    {
        Self::try_new(member_handle, sig_xs).expect("self trust inputs must be valid")
    }

    pub fn try_new<M, I>(member_handle: M, sig_xs: I) -> Result<Self>
    where
        M: IntoMemberHandle,
        I: IntoIterator<Item = [u8; 32]>,
    {
        let mut set = Self {
            member_handle: Some(member_handle.into_member_handle()?),
            sig_xs: Vec::new(),
            keystore_root: None,
        };
        set.extend_sig_xs(sig_xs);
        Ok(set)
    }

    pub fn try_new_with_keystore<M, I>(
        member_handle: M,
        sig_xs: I,
        keystore_root: PathBuf,
    ) -> Result<Self>
    where
        M: IntoMemberHandle,
        I: IntoIterator<Item = [u8; 32]>,
    {
        let mut set = Self::try_new(member_handle, sig_xs)?;
        set.keystore_root = Some(keystore_root);
        Ok(set)
    }

    pub fn insert_sig_x(&mut self, sig_x: [u8; 32]) {
        if !self.sig_xs.contains(&sig_x) {
            self.sig_xs.push(sig_x);
        }
    }

    pub fn extend_sig_xs<I>(&mut self, sig_xs: I)
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        for sig_x in sig_xs {
            self.insert_sig_x(sig_x);
        }
    }

    pub fn contains_identity(&self, identity: &TrustIdentity) -> Result<bool> {
        let Some(member_handle) = self.member_handle.as_ref() else {
            return Ok(false);
        };
        if identity.member_handle_value() != member_handle {
            return Ok(false);
        }
        if self.sig_xs.contains(identity.sig_x()) {
            return Ok(true);
        }

        self.load_keystore_identity(identity)
    }

    pub fn member_handle(&self) -> Option<&str> {
        self.member_handle.as_ref().map(MemberHandle::as_str)
    }

    fn load_keystore_identity(&self, identity: &TrustIdentity) -> Result<bool> {
        let Some(member_handle) = self.member_handle.as_ref() else {
            return Ok(false);
        };
        let Some(keystore_root) = self.keystore_root.as_ref() else {
            return Ok(false);
        };

        let public_key_path = get_public_key_file_path_from_root(
            keystore_root,
            member_handle.as_str(),
            identity.kid(),
        );
        if !public_key_path.exists() {
            return Ok(false);
        }

        let public_key = load_public_key(keystore_root, member_handle.as_str(), identity.kid())?;
        validate_keystore_identity(member_handle, identity, &public_key)?;
        let resolved = TrustIdentity::from_public_key(&public_key)?;
        Ok(resolved.sig_x() == identity.sig_x())
    }
}

fn validate_keystore_identity(
    member_handle: &MemberHandle,
    identity: &TrustIdentity,
    public_key: &PublicKey,
) -> Result<()> {
    if public_key.protected.subject_handle != member_handle.as_str() {
        return Err(crate::Error::build_config_error(format!(
            "Local self key member_handle mismatch for kid '{}': expected '{}', got '{}'",
            identity.kid(),
            member_handle,
            public_key.protected.subject_handle
        )));
    }
    if public_key.protected.kid != identity.kid() {
        return Err(crate::Error::build_config_error(format!(
            "Local self key kid mismatch for member '{}': expected '{}', got '{}'",
            member_handle,
            identity.kid(),
            public_key.protected.kid
        )));
    }
    Ok(())
}
