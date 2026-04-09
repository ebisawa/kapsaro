// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::identity::{Kid, MemberId};
use crate::model::public_key::PublicKey;
use crate::support::base64url::b64_decode_array;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustIdentity {
    member_id: MemberId,
    kid: Kid,
    sig_x: [u8; 32],
}

impl TrustIdentity {
    pub fn new<M, K>(member_id: M, kid: K, sig_x: [u8; 32]) -> Self
    where
        M: IntoMemberId,
        K: IntoKid,
    {
        Self::try_new(member_id, kid, sig_x).expect("trust identity inputs must be valid")
    }

    pub fn try_new<M, K>(member_id: M, kid: K, sig_x: [u8; 32]) -> Result<Self>
    where
        M: IntoMemberId,
        K: IntoKid,
    {
        Ok(Self {
            member_id: member_id.into_member_id()?,
            kid: kid.into_kid()?,
            sig_x,
        })
    }

    pub fn from_public_key(public_key: &PublicKey) -> Result<Self> {
        Self::try_new(
            public_key.protected.member_id.clone(),
            public_key.protected.kid.clone(),
            b64_decode_array(
                &public_key.protected.identity.keys.sig.x,
                "signer Ed25519 public key",
            )?,
        )
    }

    pub fn member_id(&self) -> &str {
        self.member_id.as_str()
    }

    pub fn member_id_value(&self) -> &MemberId {
        &self.member_id
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

pub trait IntoMemberId {
    fn into_member_id(self) -> Result<MemberId>;
}

impl IntoMemberId for MemberId {
    fn into_member_id(self) -> Result<MemberId> {
        Ok(self)
    }
}

impl IntoMemberId for String {
    fn into_member_id(self) -> Result<MemberId> {
        MemberId::try_from(self)
    }
}

impl IntoMemberId for &str {
    fn into_member_id(self) -> Result<MemberId> {
        MemberId::try_from(self)
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
