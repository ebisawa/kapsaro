// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Self-trust identification.
//! Recognises the operator's own keys so they are never queued for review.

use subtle::{Choice, ConstantTimeEq};

use crate::feature::context::crypto::{LocalKeyIdentity, PublicKeyMatch};
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::{ErrorKind, Result};

use super::identity::{IntoMemberHandle, TrustIdentity};

#[derive(Debug, Clone, Default)]
pub struct SelfTrustSet {
    member_handle: Option<MemberHandle>,
    sig_xs: Vec<[u8; 32]>,
    keystore: Option<KeystoreAccess>,
}

impl SelfTrustSet {
    /// Build a self-trust set from inputs known to be valid.
    ///
    /// Production always goes through `try_new` or the keystore-backed form
    /// because its inputs come off the wire; the panicking form keeps the
    /// tests that spell a literal handle readable.
    #[cfg(test)]
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
            keystore: None,
        };
        set.extend_sig_xs(sig_xs);
        Ok(set)
    }

    pub(crate) fn try_new_with_keystore<M, I>(
        member_handle: M,
        sig_xs: I,
        keystore: KeystoreAccess,
    ) -> Result<Self>
    where
        M: IntoMemberHandle,
        I: IntoIterator<Item = [u8; 32]>,
    {
        let mut set = Self::try_new(member_handle, sig_xs)?;
        set.keystore = Some(keystore);
        Ok(set)
    }

    pub fn insert_sig_x(&mut self, sig_x: [u8; 32]) {
        if !self.contains_sig_x(&sig_x) {
            self.sig_xs.push(sig_x);
        }
    }

    /// Report whether one of the held keys is this Ed25519 public key.
    ///
    /// Every candidate is folded in before the answer is read, so neither the
    /// match itself nor the position it was found at is timed.
    fn contains_sig_x(&self, sig_x: &[u8; 32]) -> bool {
        self.sig_xs
            .iter()
            .fold(Choice::from(0u8), |found, known| {
                found | known.as_slice().ct_eq(sig_x.as_slice())
            })
            .into()
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
        if self.contains_sig_x(identity.sig_x()) {
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
        let Some(keystore) = self.keystore.as_ref() else {
            return Ok(false);
        };
        let kid = Kid::try_from(identity.kid())?;
        let public_key = match keystore.load_public_key(member_handle, &kid) {
            Ok(public_key) => public_key,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };

        // The stored key is read out of the directory the handle and kid name,
        // so a document disagreeing with either is local state that contradicts
        // itself, not a key belonging to someone else.
        let expected = LocalKeyIdentity::new(member_handle.clone(), kid, *identity.sig_x());
        match expected.check_public_key(&public_key)? {
            PublicKeyMatch::Matches => Ok(true),
            PublicKeyMatch::SignaturePublicKeyMismatch => Ok(false),
            PublicKeyMatch::MemberHandleMismatch => Err(crate::Error::build_config_error(format!(
                "Local self key member_handle mismatch for kid '{}': expected '{}', got '{}'",
                identity.kid(),
                member_handle,
                public_key.protected.subject_handle
            ))),
            PublicKeyMatch::KidMismatch => Err(crate::Error::build_config_error(format!(
                "Local self key kid mismatch for member '{}': expected '{}', got '{}'",
                member_handle,
                identity.kid(),
                public_key.protected.kid
            ))),
        }
    }
}
