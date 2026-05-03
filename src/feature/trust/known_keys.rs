// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Known keys CRUD operations and integrity checks.

use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::KnownKey;
use crate::support::kid::resolve_unique_kid;
use crate::{Error, Result};
use time::format_description::well_known::Rfc3339;
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
    pub fn new<M, K>(member_handle: M, kid: K) -> Self
    where
        M: IntoKnownMemberHandle,
        K: IntoKnownKid,
    {
        Self::try_new(member_handle, kid).expect("known key identity inputs must be valid")
    }

    pub fn try_new<M, K>(member_handle: M, kid: K) -> Result<Self>
    where
        M: IntoKnownMemberHandle,
        K: IntoKnownKid,
    {
        Ok(Self {
            member_handle: member_handle.into_member_handle()?,
            kid: kid.into_kid()?,
        })
    }

    pub fn member_handle(&self) -> &str {
        self.member_handle.as_str()
    }

    pub fn member_handle_value(&self) -> &MemberHandle {
        &self.member_handle
    }

    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }

    pub fn kid_value(&self) -> &Kid {
        &self.kid
    }
}

pub trait IntoKnownMemberHandle {
    fn into_member_handle(self) -> Result<MemberHandle>;
}

impl IntoKnownMemberHandle for MemberHandle {
    fn into_member_handle(self) -> Result<MemberHandle> {
        Ok(self)
    }
}

impl IntoKnownMemberHandle for String {
    fn into_member_handle(self) -> Result<MemberHandle> {
        MemberHandle::try_from(self)
    }
}

impl IntoKnownMemberHandle for &str {
    fn into_member_handle(self) -> Result<MemberHandle> {
        MemberHandle::try_from(self)
    }
}

pub trait IntoKnownKid {
    fn into_kid(self) -> Result<Kid>;
}

impl IntoKnownKid for Kid {
    fn into_kid(self) -> Result<Kid> {
        Ok(self)
    }
}

impl IntoKnownKid for String {
    fn into_kid(self) -> Result<Kid> {
        Kid::try_from(self)
    }
}

impl IntoKnownKid for &str {
    fn into_kid(self) -> Result<Kid> {
        Kid::try_from(self)
    }
}

/// Add a known key entry.
///
/// - Different subject_handle with same kid -> integrity anomaly error
/// - Same subject_handle and kid -> already approved, no update (`Ok(false)`)
/// - New `(subject_handle, kid)` -> inserted (`Ok(true)`)
pub fn add_known_key(keys: &mut Vec<KnownKey>, new_key: KnownKey) -> Result<bool> {
    validate_kid_integrity(keys, &new_key.kid, &new_key.subject_handle)?;

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
        .ok_or_else(|| Error::NotFound {
            message: format!("kid '{}' not found in known_keys", kid),
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
    let mut removed = Vec::new();
    let mut retained = Vec::with_capacity(keys.len());

    for key in keys.drain(..) {
        let approved_at =
            OffsetDateTime::parse(&key.approved_at, &Rfc3339).map_err(|e| Error::Parse {
                message: format!(
                    "Failed to parse known_keys[].approved_at '{}': {}",
                    key.approved_at, e
                ),
                source: Some(Box::new(e)),
            })?;

        if approved_at < older_than {
            removed.push(key);
        } else {
            retained.push(key);
        }
    }

    *keys = retained;
    Ok(removed)
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
    validate_kid_integrity(keys, candidate_kid, candidate_member_handle)?;
    if find_known_key(keys, candidate_kid).is_some() {
        Ok(KnownKeyJudgment::Existing)
    } else {
        Ok(KnownKeyJudgment::New)
    }
}

/// Validate that a candidate kid does not conflict with existing known_keys.
///
/// Fails if the same kid exists with a different subject_handle.
pub fn validate_kid_integrity(
    keys: &[KnownKey],
    candidate_kid: &str,
    candidate_member_handle: &str,
) -> Result<()> {
    if let Some(existing) = find_known_key(keys, candidate_kid) {
        if existing.subject_handle != candidate_member_handle {
            return Err(Error::Verify {
                rule: "E_TRUST_KID_INTEGRITY_ANOMALY".to_string(),
                message: format!(
                    "kid '{}' exists with subject_handle '{}' but candidate has subject_handle '{}'",
                    candidate_kid, existing.subject_handle, candidate_member_handle
                ),
            });
        }
    }
    Ok(())
}
