// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::model::identity::MemberId;
use crate::model::public_key::PublicKey;

use super::identity::TrustIdentity;

#[derive(Debug, Clone, Copy)]
pub struct ActiveMemberSnapshot<'a> {
    members_by_kid: &'a BTreeMap<String, PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentMemberMatch {
    Missing,
    Matched,
    MemberIdMismatch { active_member_id: MemberId },
}

impl<'a> ActiveMemberSnapshot<'a> {
    pub fn new(members_by_kid: &'a BTreeMap<String, PublicKey>) -> Self {
        Self { members_by_kid }
    }

    pub fn judge_identity_match(&self, identity: &TrustIdentity) -> CurrentMemberMatch {
        let Some(member) = self.members_by_kid.get(identity.kid()) else {
            return CurrentMemberMatch::Missing;
        };

        let active_member_id = MemberId::try_from(member.protected.member_id.clone())
            .expect("workspace member_id must be valid");
        if active_member_id == *identity.member_id_value() {
            CurrentMemberMatch::Matched
        } else {
            CurrentMemberMatch::MemberIdMismatch { active_member_id }
        }
    }
}
