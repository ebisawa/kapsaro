// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::model::identity::MemberHandle;
use crate::model::trust_store::KnownKey;
use crate::{Error, Result};

use super::identity::TrustIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownKeyMatch {
    Missing,
    Exact,
    MemberHandleMismatch { known_member_handle: MemberHandle },
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
            if let KnownKeyMatch::MemberHandleMismatch {
                known_member_handle,
            } = self.judge_identity_match(recipient)
            {
                return Err(Error::build_verification_error("E_TRUST_KID_INTEGRITY_ANOMALY".to_string(), format!(
                        "kid '{}' exists with member_handle '{}' but candidate has member_handle '{}'",
                        recipient.kid(),
                        known_member_handle,
                        recipient.member_handle()
                    )));
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
    if let Some(known_member_handle) =
        find_known_member_handle(known_keys, additional_known_keys, identity.kid())
    {
        if known_member_handle == *identity.member_handle_value() {
            KnownKeyMatch::Exact
        } else {
            KnownKeyMatch::MemberHandleMismatch {
                known_member_handle,
            }
        }
    } else {
        KnownKeyMatch::Missing
    }
}

fn find_known_member_handle(
    known_keys: &[KnownKey],
    additional_known_keys: &[KnownKeyIdentity],
    kid: &str,
) -> Option<MemberHandle> {
    additional_known_keys
        .iter()
        .find(|identity| identity.kid() == kid)
        .map(|identity| identity.member_handle_value().clone())
        .or_else(|| {
            known_keys
                .iter()
                .find(|known_key| known_key.kid == kid)
                .map(|known_key| {
                    MemberHandle::try_from(known_key.subject_handle.clone())
                        .expect("known key member_handle must be valid")
                })
        })
}
