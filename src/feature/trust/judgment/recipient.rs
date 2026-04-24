// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::Result;

use super::identity::TrustIdentity;
use super::known_key::{AdditionalKnownKeyCache, KnownKeyCache, KnownKeyMatch};
use super::self_trust::SelfTrustSet;

pub fn judge_recipients_trust(
    recipients: &[TrustIdentity],
    known_keys: &KnownKeyCache<'_>,
    self_trust: &SelfTrustSet,
) -> Result<Vec<KnownKeyIdentity>> {
    judge_recipients_trust_with_match(recipients, self_trust, |identity| {
        known_keys.judge_identity_match(identity)
    })
}

pub(crate) fn judge_recipients_trust_with_additional(
    recipients: &[TrustIdentity],
    known_keys: &AdditionalKnownKeyCache<'_>,
    self_trust: &SelfTrustSet,
) -> Result<Vec<KnownKeyIdentity>> {
    judge_recipients_trust_with_match(recipients, self_trust, |identity| {
        known_keys.judge_identity_match(identity)
    })
}

fn judge_recipients_trust_with_match<MatchKnown>(
    recipients: &[TrustIdentity],
    self_trust: &SelfTrustSet,
    match_known: MatchKnown,
) -> Result<Vec<KnownKeyIdentity>>
where
    MatchKnown: Fn(&TrustIdentity) -> KnownKeyMatch,
{
    let mut needs_approval = Vec::new();

    for recipient in recipients {
        if is_self_key(recipient, self_trust)? {
            continue;
        }

        if matches!(match_known(recipient), KnownKeyMatch::Exact) {
            continue;
        }

        needs_approval.push(KnownKeyIdentity::new(
            recipient.member_id_value().clone(),
            recipient.kid_value().clone(),
        ));
    }

    Ok(needs_approval)
}

fn is_self_key(identity: &TrustIdentity, self_trust: &SelfTrustSet) -> Result<bool> {
    self_trust.contains_identity(identity)
}
