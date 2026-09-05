// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Decides which recipients of a document still need trust approval.
//! Skips self keys and keys already known exactly, collecting the rest for approval.

use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::Result;

use super::identity::TrustIdentity;
use super::known_key::{KnownKeyCache, KnownKeyMatch};
use super::self_trust::SelfTrustSet;

pub fn judge_recipients_trust(
    recipients: &[TrustIdentity],
    known_keys: &KnownKeyCache<'_>,
    self_trust: &SelfTrustSet,
) -> Result<Vec<KnownKeyIdentity>> {
    let mut needs_approval = Vec::new();

    for recipient in recipients {
        if is_self_key(recipient, self_trust)? {
            continue;
        }

        if matches!(
            known_keys.judge_identity_match(recipient),
            KnownKeyMatch::Exact
        ) {
            continue;
        }

        needs_approval.push(KnownKeyIdentity::try_new(
            recipient.member_handle_value().clone(),
            recipient.kid_value().clone(),
        )?);
    }

    Ok(needs_approval)
}

fn is_self_key(identity: &TrustIdentity, self_trust: &SelfTrustSet) -> Result<bool> {
    self_trust.contains_identity(identity)
}
