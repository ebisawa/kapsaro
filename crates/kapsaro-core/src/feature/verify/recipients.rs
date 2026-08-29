// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient public key verification.

use super::public_key::verify_recipient_public_keys;
use crate::io::keystore::public_key_source::PublicKeySource;
use crate::model::identity::MemberHandle;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;

/// Load and verify recipient public keys in one step.
pub fn verify_recipient_public_keys_from_source(
    pub_key_source: &dyn PublicKeySource,
    member_handles: &[String],
) -> Result<Vec<VerifiedRecipientKey>> {
    let member_handles = member_handles
        .iter()
        .map(|handle| MemberHandle::try_from(handle.as_str()))
        .collect::<Result<Vec<_>>>()?;
    let pubkeys = pub_key_source.load_public_keys_for_member_handles(&member_handles)?;
    verify_recipient_public_keys(&pubkeys)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_verify_recipients_test.rs"]
mod feature_verify_recipients_test;
