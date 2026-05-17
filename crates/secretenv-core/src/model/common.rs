// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common structures
//!
//! Shared structures used by file-enc and kv-enc formats

use crate::crypto::types::data::{Ciphertext, Enc};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::wire::algorithm;
use crate::support::codec::base64_public::decode_base64url_nopad_array;
use crate::support::kid::format_kid_display_lossy;
use crate::support::limits::validate_wrap_count;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Wrapped key item (HPKE-encrypted content key)
///
/// Used in both FileEncDocument and EncryptedKVValue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WrapItem {
    /// Recipient handle.
    #[serde(rename = "rh")]
    pub recipient_handle: String,

    /// Recipient key statement ID in canonical Crockford Base32 form
    pub kid: String,

    /// HPKE algorithm identifier (e.g., "hpke-32-1-2")
    pub alg: String,

    /// Encapsulated key (base64url)
    pub enc: String,

    /// Wrapped content key ciphertext (base64url)
    pub ct: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapAlgorithm {
    Hpke32_1_3,
}

impl WrapAlgorithm {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305 => Ok(Self::Hpke32_1_3),
            _ => Err(Error::build_crypto_error(format!(
                "Unsupported HPKE algorithm: {} (expected: {})",
                value,
                algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hpke32_1_3 => algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
        }
    }
}

/// Parsed recipient wrap with validated domain fields.
#[derive(Debug, Clone)]
pub struct RecipientWrap {
    recipient_handle: MemberHandle,
    kid: Kid,
    alg: WrapAlgorithm,
    enc: Enc,
    ct: Ciphertext,
}

impl RecipientWrap {
    pub fn parse(item: &WrapItem) -> Result<Self> {
        let recipient_handle = MemberHandle::try_from(item.recipient_handle.clone())?;
        let kid = Kid::try_from(item.kid.clone())?;
        let alg = WrapAlgorithm::parse(&item.alg)?;
        let enc = Enc::from(decode_base64url_nopad_array::<32>(&item.enc, "enc")?.to_vec());
        let ct = Ciphertext::from(decode_base64url_nopad_array::<48>(&item.ct, "ct")?.to_vec());
        Ok(Self {
            recipient_handle,
            kid,
            alg,
            enc,
            ct,
        })
    }

    pub fn recipient_handle(&self) -> &MemberHandle {
        &self.recipient_handle
    }

    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    pub fn alg(&self) -> WrapAlgorithm {
        self.alg
    }

    pub fn enc(&self) -> &Enc {
        &self.enc
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ct
    }
}

/// Parsed set of recipient wraps.
#[derive(Debug, Clone)]
pub struct WrapSet {
    items: Vec<RecipientWrap>,
}

impl WrapSet {
    pub fn parse(wrap_items: &[WrapItem], context: &str) -> Result<Self> {
        validate_wrap_count(wrap_items.len(), context)?;

        let mut seen_recipient_handles = HashSet::new();
        let mut items = Vec::with_capacity(wrap_items.len());
        for item in wrap_items {
            if !seen_recipient_handles.insert(item.recipient_handle.as_str()) {
                return Err(Error::build_verification_error(
                    "E_DUPLICATE_RECIPIENT_HANDLE".to_string(),
                    format!(
                        "{} contains duplicate rh '{}' in wrap",
                        context, item.recipient_handle
                    ),
                ));
            }
            items.push(RecipientWrap::parse(item)?);
        }

        Ok(Self { items })
    }

    pub fn items(&self) -> &[RecipientWrap] {
        &self.items
    }

    pub fn find_by_kid_for_member(&self, kid: &str, member_handle: &str) -> Result<&RecipientWrap> {
        let wrap_item = self
            .items
            .iter()
            .find(|item| item.kid.as_str() == kid)
            .ok_or_else(|| {
                Error::build_crypto_error(format!(
                    "No wrap found for kid '{}' (member: {})",
                    format_kid_display_lossy(kid),
                    member_handle
                ))
            })?;

        if wrap_item.recipient_handle.as_str() != member_handle {
            return Err(Error::build_crypto_error(format!(
                "wrap_item.rh '{}' does not match member_handle '{}' for kid '{}'",
                wrap_item.recipient_handle,
                member_handle,
                format_kid_display_lossy(kid)
            )));
        }

        Ok(wrap_item)
    }

    pub fn self_wrap_kids(&self, member_handle: &str) -> Vec<Kid> {
        let mut kids = Vec::new();
        for item in &self.items {
            if item.recipient_handle.as_str() != member_handle || kids.contains(&item.kid) {
                continue;
            }
            kids.push(item.kid.clone());
        }
        kids
    }
}

/// Removed recipient record
///
/// Tracks disclosure history for removed recipients
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RemovedRecipient {
    /// Recipient handle that was removed.
    #[serde(rename = "rh")]
    pub recipient_handle: String,

    /// Recipient key statement ID copied from `wrap_item.kid`
    pub kid: String,

    /// Timestamp when the recipient was removed (RFC 3339)
    pub removed_at: String,
}

/// Validate wrap items against shared structural constraints.
pub fn validate_wrap_items(wrap_items: &[WrapItem], context: &str) -> Result<()> {
    WrapSet::parse(wrap_items, context)?;
    Ok(())
}

/// Normalizes a list of recipients by sorting and removing duplicates
///
/// This ensures consistent ordering for HPKE info generation and deduplication.
/// Recipients are sorted lexicographically (case-sensitive).
///
/// # Arguments
/// * `recipients` - Slice of recipient handle strings
///
/// # Returns
/// A new Vec with sorted, deduplicated recipients
///
/// # Example
/// ```ignore
/// use secretenv_core::model::common::normalize_recipients;
///
/// let recipients = vec!["bob@example.com".to_string(), "alice@example.com".to_string(), "bob@example.com".to_string()];
/// let normalized = normalize_recipients(&recipients);
/// assert_eq!(normalized, vec!["alice@example.com", "bob@example.com"]);
/// ```
pub fn normalize_recipients(recipients: &[String]) -> Vec<String> {
    let mut sorted = recipients.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}
