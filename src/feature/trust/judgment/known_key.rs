// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::model::identity::MemberId;
use crate::model::trust_store::KnownKey;
use crate::{Error, Result};

use super::identity::TrustIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownKeyMatch {
    Missing,
    Exact,
    MemberIdMismatch { known_member_id: MemberId },
}

#[derive(Clone, Copy)]
pub struct KnownKeyCache<'a> {
    known_keys: &'a [KnownKey],
}

#[derive(Clone, Copy)]
pub struct AdditionalKnownKeyCache<'a> {
    known_keys: &'a [KnownKey],
    additional_known_keys: &'a [KnownKeyIdentity],
}

impl<'a> KnownKeyCache<'a> {
    pub fn new(known_keys: &'a [KnownKey]) -> Self {
        Self { known_keys }
    }

    pub fn judge_identity_match(&self, identity: &TrustIdentity) -> KnownKeyMatch {
        judge_known_identity_match(self.known_keys, &[], identity)
    }
}

impl<'a> AdditionalKnownKeyCache<'a> {
    pub fn new(known_keys: &'a [KnownKey], additional_known_keys: &'a [KnownKeyIdentity]) -> Self {
        Self {
            known_keys,
            additional_known_keys,
        }
    }

    pub fn judge_identity_match(&self, identity: &TrustIdentity) -> KnownKeyMatch {
        judge_known_identity_match(self.known_keys, self.additional_known_keys, identity)
    }

    pub fn validate_recipient_integrity(&self, recipients: &[TrustIdentity]) -> Result<()> {
        for recipient in recipients {
            if let KnownKeyMatch::MemberIdMismatch { known_member_id } =
                self.judge_identity_match(recipient)
            {
                return Err(Error::Verify {
                    rule: "E_TRUST_KID_INTEGRITY_ANOMALY".to_string(),
                    message: format!(
                        "kid '{}' exists with member_id '{}' but candidate has member_id '{}'",
                        recipient.kid(),
                        known_member_id,
                        recipient.member_id()
                    ),
                });
            }
        }
        Ok(())
    }
}

fn judge_known_identity_match(
    known_keys: &[KnownKey],
    additional_known_keys: &[KnownKeyIdentity],
    identity: &TrustIdentity,
) -> KnownKeyMatch {
    if let Some(known_member_id) =
        find_known_member_id(known_keys, additional_known_keys, identity.kid())
    {
        if known_member_id == *identity.member_id_value() {
            KnownKeyMatch::Exact
        } else {
            KnownKeyMatch::MemberIdMismatch { known_member_id }
        }
    } else {
        KnownKeyMatch::Missing
    }
}

fn find_known_member_id(
    known_keys: &[KnownKey],
    additional_known_keys: &[KnownKeyIdentity],
    kid: &str,
) -> Option<MemberId> {
    additional_known_keys
        .iter()
        .find(|identity| identity.kid() == kid)
        .map(|identity| identity.member_id_value().clone())
        .or_else(|| {
            known_keys
                .iter()
                .find(|known_key| known_key.kid == kid)
                .map(|known_key| {
                    MemberId::try_from(known_key.member_id.clone())
                        .expect("known key member_id must be valid")
                })
        })
}
