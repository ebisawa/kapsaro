// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! The identity a trust judgment is made about.
//! Pairs a member handle with the key statement that handle names.

use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustIdentity {
    member_handle: MemberHandle,
    kid: Kid,
    sig_x: [u8; 32],
}

impl TrustIdentity {
    /// Build an identity from inputs known to be valid.
    ///
    /// Production always goes through `try_new` or `from_public_key` because
    /// its inputs come off the wire; the panicking form keeps the tests that
    /// spell a literal handle and kid readable.
    #[cfg(test)]
    pub fn new<M, K>(member_handle: M, kid: K, sig_x: [u8; 32]) -> Self
    where
        M: IntoMemberHandle,
        K: IntoKid,
    {
        Self::try_new(member_handle, kid, sig_x).expect("trust identity inputs must be valid")
    }

    pub fn try_new<M, K>(member_handle: M, kid: K, sig_x: [u8; 32]) -> Result<Self>
    where
        M: IntoMemberHandle,
        K: IntoKid,
    {
        Ok(Self {
            member_handle: member_handle.into_member_handle()?,
            kid: kid.into_kid()?,
            sig_x,
        })
    }

    /// Read the identity one stored public key states.
    ///
    /// The key id is taken as the canonical form a stored document carries.
    /// Normalizing a display form here would let a judgment be made about a key
    /// id the document itself never named, which is not the same key statement
    /// the signature covers.
    pub fn from_public_key(public_key: &PublicKey) -> Result<Self> {
        Self::try_new(
            public_key.protected.subject_handle.clone(),
            Kid::from_canonical(public_key.protected.kid.clone())?,
            decode_base64url_nopad_array(
                &public_key.protected.keys.sig.x,
                "signer Ed25519 public key",
            )?,
        )
    }

    pub fn member_handle(&self) -> &str {
        self.member_handle.as_str()
    }

    pub fn member_handle_value(&self) -> &MemberHandle {
        &self.member_handle
    }

    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }

    pub fn kid_value(&self) -> &Kid {
        &self.kid
    }

    pub fn sig_x(&self) -> &[u8; 32] {
        &self.sig_x
    }
}

pub trait IntoMemberHandle {
    fn into_member_handle(self) -> Result<MemberHandle>;
}

impl IntoMemberHandle for MemberHandle {
    fn into_member_handle(self) -> Result<MemberHandle> {
        Ok(self)
    }
}

impl IntoMemberHandle for String {
    fn into_member_handle(self) -> Result<MemberHandle> {
        MemberHandle::try_from(self)
    }
}

impl IntoMemberHandle for &str {
    fn into_member_handle(self) -> Result<MemberHandle> {
        MemberHandle::try_from(self)
    }
}

pub trait IntoKid {
    fn into_kid(self) -> Result<Kid>;
}

impl IntoKid for Kid {
    fn into_kid(self) -> Result<Kid> {
        Ok(self)
    }
}

impl IntoKid for String {
    fn into_kid(self) -> Result<Kid> {
        Kid::try_from(self)
    }
}

impl IntoKid for &str {
    fn into_kid(self) -> Result<Kid> {
        Kid::try_from(self)
    }
}
