// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Typed trust judgment logic.

mod active_member;
mod identity;
mod known_key;
mod recipient;
mod self_trust;
mod signer;

pub use active_member::{build_active_members_by_kid, ActiveMemberSnapshot};
pub use identity::TrustIdentity;
pub use known_key::{AdditionalKnownKeyCache, KnownKeyCache};

pub(crate) use identity::{IntoKid, IntoMemberHandle};
pub use recipient::judge_recipients_trust;
pub use self_trust::SelfTrustSet;
pub use signer::{judge_signer_trust, TrustJudgment};

pub(crate) use recipient::judge_recipients_trust_with_additional;
pub(crate) use signer::judge_signer_trust_with_additional;
