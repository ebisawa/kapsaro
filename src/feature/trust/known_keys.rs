// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Known keys CRUD operations and integrity checks.

use crate::model::identity::{Kid, MemberId};
use crate::model::trust_store::KnownKey;
use crate::{Error, Result};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownKeyAssessment {
    New,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KnownKeyIdentity {
    member_id: MemberId,
    kid: Kid,
}

impl KnownKeyIdentity {
    pub fn new<M, K>(member_id: M, kid: K) -> Self
    where
        M: IntoKnownMemberId,
        K: IntoKnownKid,
    {
        Self::try_new(member_id, kid).expect("known key identity inputs must be valid")
    }

    pub fn try_new<M, K>(member_id: M, kid: K) -> Result<Self>
    where
        M: IntoKnownMemberId,
        K: IntoKnownKid,
    {
        Ok(Self {
            member_id: member_id.into_member_id()?,
            kid: kid.into_kid()?,
        })
    }

    pub fn member_id(&self) -> &str {
        self.member_id.as_str()
    }

    pub fn member_id_value(&self) -> &MemberId {
        &self.member_id
    }

    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }

    pub fn kid_value(&self) -> &Kid {
        &self.kid
    }
}

pub trait IntoKnownMemberId {
    fn into_member_id(self) -> Result<MemberId>;
}

impl IntoKnownMemberId for MemberId {
    fn into_member_id(self) -> Result<MemberId> {
        Ok(self)
    }
}

impl IntoKnownMemberId for String {
    fn into_member_id(self) -> Result<MemberId> {
        MemberId::try_from(self)
    }
}

impl IntoKnownMemberId for &str {
    fn into_member_id(self) -> Result<MemberId> {
        MemberId::try_from(self)
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
/// - Different member_id with same kid → integrity anomaly error
/// - Same member_id and kid → already approved, no update (`Ok(false)`)
/// - New `(member_id, kid)` → inserted (`Ok(true)`)
pub fn add_known_key(keys: &mut Vec<KnownKey>, new_key: KnownKey) -> Result<bool> {
    validate_kid_integrity(keys, &new_key.kid, &new_key.member_id)?;

    if find_known_key(keys, &new_key.kid).is_some() {
        return Ok(false);
    }

    keys.push(new_key);
    Ok(true)
}

/// Remove a known key by kid. Returns the removed entry or error if not found.
pub fn remove_known_key(keys: &mut Vec<KnownKey>, kid: &str) -> Result<KnownKey> {
    let pos = keys
        .iter()
        .position(|k| k.kid == kid)
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

pub fn assess_known_key(
    keys: &[KnownKey],
    candidate_kid: &str,
    candidate_member_id: &str,
) -> Result<KnownKeyAssessment> {
    validate_kid_integrity(keys, candidate_kid, candidate_member_id)?;
    if find_known_key(keys, candidate_kid).is_some() {
        Ok(KnownKeyAssessment::Existing)
    } else {
        Ok(KnownKeyAssessment::New)
    }
}

/// Validate that a candidate kid does not conflict with existing known_keys.
///
/// Fails if the same kid exists with a different member_id (integrity anomaly, spec §9.4).
pub fn validate_kid_integrity(
    keys: &[KnownKey],
    candidate_kid: &str,
    candidate_member_id: &str,
) -> Result<()> {
    if let Some(existing) = find_known_key(keys, candidate_kid) {
        if existing.member_id != candidate_member_id {
            return Err(Error::Verify {
                rule: "E_TRUST_KID_INTEGRITY_ANOMALY".to_string(),
                message: format!(
                    "kid '{}' exists with member_id '{}' but candidate has member_id '{}'",
                    candidate_kid, existing.member_id, candidate_member_id
                ),
            });
        }
    }
    Ok(())
}
