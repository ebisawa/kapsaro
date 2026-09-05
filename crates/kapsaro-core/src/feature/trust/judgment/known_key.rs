// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Matches a trust identity against the known keys stored in the trust store.
//! Flags a kid bound to a different member handle than previously recorded as an integrity anomaly.

use crate::feature::trust::known_keys::build_kid_integrity_anomaly_error;
use crate::model::identity::MemberHandle;
use crate::model::trust_store::KnownKey;
use crate::Result;

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

impl<'a> KnownKeyCache<'a> {
    pub fn new(known_keys: &'a [KnownKey]) -> Self {
        Self { known_keys }
    }

    pub fn judge_identity_match(&self, identity: &TrustIdentity) -> KnownKeyMatch {
        judge_known_identity_match(self.known_keys, identity)
    }

    pub fn enforce_recipient_integrity(&self, recipients: &[TrustIdentity]) -> Result<()> {
        for recipient in recipients {
            if let KnownKeyMatch::MemberHandleMismatch {
                known_member_handle,
            } = self.judge_identity_match(recipient)
            {
                return Err(build_kid_integrity_anomaly_error(
                    recipient.kid(),
                    known_member_handle.as_str(),
                    recipient.member_handle(),
                ));
            }
        }
        Ok(())
    }
}

fn judge_known_identity_match(known_keys: &[KnownKey], identity: &TrustIdentity) -> KnownKeyMatch {
    if let Some(known_member_handle) = find_known_member_handle(known_keys, identity.kid()) {
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

fn find_known_member_handle(known_keys: &[KnownKey], kid: &str) -> Option<MemberHandle> {
    known_keys
        .iter()
        .find(|known_key| known_key.kid == kid)
        .map(|known_key| {
            MemberHandle::try_from(known_key.subject_handle.clone())
                .expect("known key member_handle must be valid")
        })
}
