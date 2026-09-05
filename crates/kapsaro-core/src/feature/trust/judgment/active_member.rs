// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Matches a trust identity against the workspace's currently active members.
//! Indexes active members by kid so a signer or recipient can be flagged as missing or handle-mismatched.

use std::collections::{BTreeMap, BTreeSet};

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
    /// The kid belongs to an active member carrying another handle.
    ///
    /// The handle travels as the active member file stores it. What makes this
    /// a mismatch is that text, so a caller that only reports it never has to
    /// answer for a stored handle that would not read back as a valid one.
    MemberHandleMismatch {
        active_member_handle: String,
    },
}

/// How one set of kids compares with the currently active ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KidSetMatch {
    Exact,
    Differs {
        missing_active_kids: Vec<String>,
        stale_kids: Vec<String>,
    },
}

/// How one public key document compares with the active member holding its kid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentKeyMatch {
    Missing,
    Matched,
    DocumentMismatch,
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
        self.judge_handle_match(identity.kid(), identity.member_handle())
    }

    /// Match one kid and the handle claimed for it against the active members.
    pub fn judge_handle_match(&self, kid: &str, member_handle: &str) -> CurrentMemberMatch {
        let Some(member) = self.members_by_kid.get(kid) else {
            return CurrentMemberMatch::Missing;
        };
        if member.protected.subject_handle == member_handle {
            CurrentMemberMatch::Matched
        } else {
            CurrentMemberMatch::MemberHandleMismatch {
                active_member_handle: member.protected.subject_handle.clone(),
            }
        }
    }

    /// Compare a set of kids with the kids the active members hold.
    ///
    /// A difference is reported from both sides, because an active member the
    /// set never named and a kid no member holds any more call for the same
    /// repair but read as different faults.
    pub fn judge_kid_set_match<'k>(&self, kids: impl IntoIterator<Item = &'k str>) -> KidSetMatch {
        let given = kids.into_iter().collect::<BTreeSet<_>>();
        let current = self
            .members_by_kid
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if given == current {
            return KidSetMatch::Exact;
        }
        KidSetMatch::Differs {
            missing_active_kids: collect_owned_difference(&current, &given),
            stale_kids: collect_owned_difference(&given, &current),
        }
    }

    /// Match one public key document against the active member holding its kid.
    pub fn judge_public_key_match(&self, key: &PublicKey) -> CurrentKeyMatch {
        match self.members_by_kid.get(&key.protected.kid) {
            None => CurrentKeyMatch::Missing,
            Some(current) if current == key => CurrentKeyMatch::Matched,
            Some(_) => CurrentKeyMatch::DocumentMismatch,
        }
    }
}

fn collect_owned_difference(left: &BTreeSet<&str>, right: &BTreeSet<&str>) -> Vec<String> {
    left.difference(right)
        .map(|kid| (*kid).to_string())
        .collect()
}
