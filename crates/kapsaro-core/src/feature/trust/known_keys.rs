// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Known keys CRUD operations and integrity checks.

use crate::feature::trust::judgment::{IntoKid, IntoMemberHandle};
use crate::feature::trust::purge::purge_records;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::KnownKey;
use crate::support::kid::resolve_unique_kid;
use crate::{Error, Result};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownKeyJudgment {
    New,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KnownKeyIdentity {
    member_handle: MemberHandle,
    kid: Kid,
}

impl KnownKeyIdentity {
    pub fn try_new<M, K>(member_handle: M, kid: K) -> Result<Self>
    where
        M: IntoMemberHandle,
        K: IntoKid,
    {
        Ok(Self {
            member_handle: member_handle.into_member_handle()?,
            kid: kid.into_kid()?,
        })
    }

    pub fn member_handle(&self) -> &str {
        self.member_handle.as_str()
    }

    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }
}

/// Add a known key entry.
///
/// - Different subject_handle with same kid -> integrity anomaly error
/// - Same subject_handle and kid -> already approved, no update (`Ok(false)`)
/// - New `(subject_handle, kid)` -> inserted (`Ok(true)`)
pub fn add_known_key(keys: &mut Vec<KnownKey>, new_key: KnownKey) -> Result<bool> {
    enforce_kid_integrity(keys, &new_key.kid, &new_key.subject_handle)?;

    if find_known_key(keys, &new_key.kid).is_some() {
        return Ok(false);
    }

    keys.push(new_key);
    Ok(true)
}

/// Remove a known key by kid. Returns the removed entry or error if not found.
pub fn remove_known_key(keys: &mut Vec<KnownKey>, kid: &str) -> Result<KnownKey> {
    let resolved_kid = resolve_unique_kid(keys.iter().map(|key| key.kid.as_str()), kid)?;
    let pos = keys
        .iter()
        .position(|k| k.kid == resolved_kid)
        .ok_or_else(|| {
            Error::build_not_found_error(format!("kid '{}' not found in known_keys", kid))
        })?;
    Ok(keys.remove(pos))
}

/// Purge known keys with approved_at older than the threshold.
///
/// Returns the removed entries.
pub fn purge_known_keys(
    keys: &mut Vec<KnownKey>,
    older_than: OffsetDateTime,
) -> Result<Vec<KnownKey>> {
    purge_records(keys, older_than)
}

/// Find a known key by kid.
pub fn find_known_key<'a>(keys: &'a [KnownKey], kid: &str) -> Option<&'a KnownKey> {
    keys.iter().find(|k| k.kid == kid)
}

pub fn judge_known_key(
    keys: &[KnownKey],
    candidate_kid: &str,
    candidate_member_handle: &str,
) -> Result<KnownKeyJudgment> {
    enforce_kid_integrity(keys, candidate_kid, candidate_member_handle)?;
    if find_known_key(keys, candidate_kid).is_some() {
        Ok(KnownKeyJudgment::Existing)
    } else {
        Ok(KnownKeyJudgment::New)
    }
}

/// Validate that a candidate kid does not conflict with existing known_keys.
///
/// Fails if the same kid exists with a different subject_handle.
pub fn enforce_kid_integrity(
    keys: &[KnownKey],
    candidate_kid: &str,
    candidate_member_handle: &str,
) -> Result<()> {
    if let Some(existing) = find_known_key(keys, candidate_kid) {
        if existing.subject_handle != candidate_member_handle {
            return Err(build_kid_integrity_anomaly_error(
                candidate_kid,
                &existing.subject_handle,
                candidate_member_handle,
            ));
        }
    }
    Ok(())
}

/// Report a kid that is already bound to another member than the candidate.
///
/// Every path that meets the anomaly states it the same way, because what the
/// operator has to look at is the same in each: the kid, the member it is
/// already recorded for, and the member now claiming it.
pub(crate) fn build_kid_integrity_anomaly_error(
    kid: &str,
    existing_member_handle: &str,
    candidate_member_handle: &str,
) -> Error {
    Error::build_verification_error(
        "E_TRUST_KID_INTEGRITY_ANOMALY".to_string(),
        format!(
            "Known key kid has conflicting subject handle.\n\
             Kid: {}\n\
             Existing subject: {}\n\
             Candidate subject: {}",
            kid, existing_member_handle, candidate_member_handle
        ),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_known_keys_test.rs"]
mod feature_trust_known_keys_test;
