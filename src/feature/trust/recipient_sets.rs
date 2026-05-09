// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact recipient set approval operations and integrity checks.

use crate::feature::trust::judgment::{SelfTrustSet, TrustIdentity};
use crate::format::jcs;
use crate::model::common::WrapItem;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::trust_store::{RecipientHandleHint, RecipientSetApprovalVia, RecipientSetRecord};
use crate::model::wire::context::HASH_DOMAIN_RECIPIENT_SET_V2;
use crate::support::codec::base64_public::encode_base64url_nopad;
use crate::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecipientSet {
    sid: Uuid,
    recipient_kids: Vec<String>,
    recipient_set_hash: String,
    recipient_handle_hints: Vec<RecipientHandleHint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientSetJudgment {
    Accepted,
    Missing,
    Changed { approved: RecipientSetRecord },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientHandleMismatch {
    pub kid: String,
    pub artifact_recipient_handle: String,
    pub active_member_handle: String,
}

#[derive(Serialize)]
struct RecipientSetHashPayload<'a> {
    domain: &'a str,
    recipient_kids: &'a [String],
}

impl ArtifactRecipientSet {
    pub fn new(sid: Uuid, recipient_kids: Vec<String>) -> Result<Self> {
        let recipient_kids = normalize_recipient_kids(recipient_kids)?;
        let recipient_set_hash = compute_recipient_set_hash(&recipient_kids)?;
        Ok(Self {
            sid,
            recipient_kids,
            recipient_set_hash,
            recipient_handle_hints: Vec::new(),
        })
    }

    pub fn from_wrap_items(sid: Uuid, wrap_items: &[WrapItem]) -> Result<Self> {
        let mut set = Self::new(
            sid,
            wrap_items.iter().map(|item| item.kid.clone()).collect(),
        )?;
        set.recipient_handle_hints = build_recipient_handle_hints(wrap_items)?;
        Ok(set)
    }

    pub fn sid(&self) -> Uuid {
        self.sid
    }

    pub fn sid_string(&self) -> String {
        self.sid.to_string()
    }

    pub fn recipient_kids(&self) -> &[String] {
        &self.recipient_kids
    }

    pub fn recipient_set_hash(&self) -> &str {
        &self.recipient_set_hash
    }

    pub fn recipient_handle_hints(&self) -> &[RecipientHandleHint] {
        &self.recipient_handle_hints
    }

    pub fn into_record(self, approved_at: String) -> RecipientSetRecord {
        RecipientSetRecord {
            sid: self.sid.to_string(),
            recipient_kids: self.recipient_kids,
            recipient_set_hash: self.recipient_set_hash,
            approved_at,
            approved_via: RecipientSetApprovalVia::ManualReview,
            recipient_handle_hints: non_empty_hints(self.recipient_handle_hints),
        }
    }
}

fn build_recipient_handle_hints(wrap_items: &[WrapItem]) -> Result<Vec<RecipientHandleHint>> {
    let mut hints = Vec::with_capacity(wrap_items.len());
    for item in wrap_items {
        hints.push(RecipientHandleHint {
            kid: Kid::try_from(item.kid.clone())?.into_string(),
            recipient_handle: MemberHandle::try_from(item.recipient_handle.clone())?.into_string(),
        });
    }
    hints.sort_by(|left, right| left.kid.cmp(&right.kid));
    Ok(hints)
}

fn non_empty_hints(hints: Vec<RecipientHandleHint>) -> Option<Vec<RecipientHandleHint>> {
    if hints.is_empty() {
        None
    } else {
        Some(hints)
    }
}

pub fn normalize_recipient_kids(recipient_kids: Vec<String>) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    for kid in recipient_kids {
        let kid = Kid::try_from(kid)?.into_string();
        if !seen.insert(kid.clone()) {
            return Err(Error::Verify {
                rule: "E_RECIPIENT_SET_DUPLICATE_KID".to_string(),
                message: format!("Duplicate kid '{}' in recipient set", kid),
            });
        }
    }
    Ok(seen.into_iter().collect())
}

pub fn compute_recipient_set_hash(recipient_kids: &[String]) -> Result<String> {
    let canonical = jcs::normalize(&RecipientSetHashPayload {
        domain: HASH_DOMAIN_RECIPIENT_SET_V2,
        recipient_kids,
    })?;
    let digest = Sha256::digest(&canonical);
    Ok(encode_base64url_nopad(&digest))
}

pub fn validate_recipient_set_record(record: &RecipientSetRecord) -> Result<()> {
    Uuid::parse_str(&record.sid).map_err(|e| Error::Verify {
        rule: "E_RECIPIENT_SET_INVALID_SID".to_string(),
        message: format!("recipient_sets[].sid must be a UUID: {}", e),
    })?;
    let normalized = normalize_recipient_kids(record.recipient_kids.clone())?;
    if normalized != record.recipient_kids {
        return Err(Error::Verify {
            rule: "E_RECIPIENT_SET_KIDS_NOT_CANONICAL".to_string(),
            message: format!(
                "recipient_sets entry for sid '{}' must use sorted canonical recipient_kids",
                record.sid
            ),
        });
    }
    let expected_hash = compute_recipient_set_hash(&record.recipient_kids)?;
    if expected_hash != record.recipient_set_hash {
        return Err(Error::Verify {
            rule: "E_RECIPIENT_SET_HASH_MISMATCH".to_string(),
            message: format!("recipient_set_hash mismatch for sid '{}'", record.sid),
        });
    }
    validate_approved_at(&record.approved_at)
}

pub fn judge_recipient_set(
    records: &[RecipientSetRecord],
    current: &ArtifactRecipientSet,
) -> RecipientSetJudgment {
    let Some(record) = records
        .iter()
        .find(|record| record.sid == current.sid_string())
    else {
        return RecipientSetJudgment::Missing;
    };
    if record.recipient_kids == current.recipient_kids {
        RecipientSetJudgment::Accepted
    } else {
        RecipientSetJudgment::Changed {
            approved: record.clone(),
        }
    }
}

pub fn find_recipient_handle_mismatch(
    current: &ArtifactRecipientSet,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
) -> Option<RecipientHandleMismatch> {
    current.recipient_handle_hints().iter().find_map(|hint| {
        let active_member = active_members_by_kid.get(&hint.kid)?;
        let active_member_handle = &active_member.protected.subject_handle;
        if active_member_handle == &hint.recipient_handle {
            None
        } else {
            Some(RecipientHandleMismatch {
                kid: hint.kid.clone(),
                artifact_recipient_handle: hint.recipient_handle.clone(),
                active_member_handle: active_member_handle.clone(),
            })
        }
    })
}

pub fn is_signer_in_recipient_set(
    signer_kid: &str,
    current: &ArtifactRecipientSet,
) -> Result<bool> {
    let signer_kid = Kid::try_from(signer_kid.to_string())?.into_string();
    Ok(current
        .recipient_kids()
        .iter()
        .any(|kid| kid == &signer_kid))
}

pub fn is_self_only_recipient_set(
    current: &ArtifactRecipientSet,
    active_members_by_kid: &BTreeMap<String, PublicKey>,
    self_trust: &SelfTrustSet,
) -> Result<bool> {
    let [kid] = current.recipient_kids() else {
        return Ok(false);
    };
    let Some(active_member) = active_members_by_kid.get(kid) else {
        return Ok(false);
    };
    let identity = TrustIdentity::from_public_key(active_member)?;
    self_trust.contains_identity(&identity)
}

pub fn upsert_recipient_set(
    records: &mut Vec<RecipientSetRecord>,
    current: ArtifactRecipientSet,
    approved_at: String,
) -> bool {
    let sid = current.sid_string();
    let new_record = current.into_record(approved_at);
    if let Some(record) = records.iter_mut().find(|record| record.sid == sid) {
        if *record == new_record {
            return false;
        }
        *record = new_record;
        return true;
    }
    records.push(new_record);
    true
}

pub fn remove_recipient_set(
    records: &mut Vec<RecipientSetRecord>,
    sid: &str,
) -> Result<RecipientSetRecord> {
    let sid = Uuid::parse_str(sid)
        .map(|sid| sid.to_string())
        .map_err(|e| Error::InvalidArgument {
            message: format!("Invalid sid '{}': {}", sid, e),
        })?;
    let pos = records
        .iter()
        .position(|record| record.sid == sid)
        .ok_or_else(|| Error::NotFound {
            message: format!("sid '{}' not found in recipient_sets", sid),
        })?;
    Ok(records.remove(pos))
}

pub fn purge_recipient_sets(
    records: &mut Vec<RecipientSetRecord>,
    older_than: OffsetDateTime,
) -> Result<Vec<RecipientSetRecord>> {
    let mut removed = Vec::new();
    let mut retained = Vec::with_capacity(records.len());
    for record in records.drain(..) {
        let approved_at =
            OffsetDateTime::parse(&record.approved_at, &Rfc3339).map_err(|e| Error::Parse {
                message: format!(
                    "Failed to parse recipient_sets[].approved_at '{}': {}",
                    record.approved_at, e
                ),
                source: Some(Box::new(e)),
            })?;
        if approved_at < older_than {
            removed.push(record);
        } else {
            retained.push(record);
        }
    }
    *records = retained;
    Ok(removed)
}

fn validate_approved_at(approved_at: &str) -> Result<()> {
    if !approved_at.ends_with('Z') {
        return Err(Error::Verify {
            rule: "E_TRUST_TIMESTAMP_NOT_UTC".to_string(),
            message: format!(
                "recipient_sets[].approved_at must end with 'Z' (UTC): '{}'",
                approved_at
            ),
        });
    }
    OffsetDateTime::parse(approved_at, &Rfc3339).map_err(|e| Error::Verify {
        rule: "E_TRUST_TIMESTAMP_INVALID".to_string(),
        message: format!(
            "recipient_sets[].approved_at must be a valid RFC 3339 UTC timestamp: '{}' ({})",
            approved_at, e
        ),
    })?;
    Ok(())
}
