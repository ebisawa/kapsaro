// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Typed trust judgment logic.

mod active_member;
mod identity;
mod known_key;
mod recipient;
mod self_trust;
mod signer;

pub use active_member::{
    build_active_members_by_kid, ActiveMemberSnapshot, CurrentKeyMatch, CurrentMemberMatch,
    KidSetMatch,
};
pub use identity::TrustIdentity;
pub use known_key::KnownKeyCache;

pub(crate) use identity::{IntoKid, IntoMemberHandle};
pub use recipient::judge_recipients_trust;
pub use self_trust::SelfTrustSet;
pub use signer::{enforce_signer_judgment, judge_signer_trust, SignerAcceptance, TrustJudgment};

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_judgment_test.rs"]
mod feature_trust_judgment_test;
