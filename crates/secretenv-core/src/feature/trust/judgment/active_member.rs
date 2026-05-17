// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::model::identity::MemberHandle;
use crate::model::public_key::PublicKey;
use crate::Result;

use super::identity::TrustIdentity;

#[derive(Debug, Clone, Copy)]
pub struct ActiveMemberSnapshot<'a> {
    members_by_kid: &'a BTreeMap<String, PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentMemberMatch {
    Missing,
    Matched,
    MemberHandleMismatch { active_member_handle: MemberHandle },
}

pub fn build_active_members_by_kid(
    active_members: &[PublicKey],
) -> Result<BTreeMap<String, PublicKey>> {
    let mut active_members_by_kid = BTreeMap::new();
    for member in active_members {
        let kid = member.protected.kid.clone();
        if active_members_by_kid
            .insert(kid.clone(), member.clone())
            .is_some()
        {
            return Err(crate::Error::build_config_error(format!(
                "Ambiguous key: kid '{}' found in multiple members",
                kid
            )));
        }
    }
    Ok(active_members_by_kid)
}

impl<'a> ActiveMemberSnapshot<'a> {
    pub fn new(members_by_kid: &'a BTreeMap<String, PublicKey>) -> Self {
        Self { members_by_kid }
    }

    pub fn judge_identity_match(&self, identity: &TrustIdentity) -> CurrentMemberMatch {
        let Some(member) = self.members_by_kid.get(identity.kid()) else {
            return CurrentMemberMatch::Missing;
        };

        let active_member_handle = MemberHandle::try_from(member.protected.subject_handle.clone())
            .expect("workspace member_handle must be valid");
        if active_member_handle == *identity.member_handle_value() {
            CurrentMemberMatch::Matched
        } else {
            CurrentMemberMatch::MemberHandleMismatch {
                active_member_handle,
            }
        }
    }
}
