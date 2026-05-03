// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common structures
//!
//! Shared structures used by file-enc and kv-enc formats

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

/// Removed recipient record
///
/// Tracks disclosure history for removed recipients
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RemovedRecipient {
    /// Recipient handle that was removed.
    pub recipient_handle: String,

    /// Recipient key statement ID copied from `wrap_item.kid`
    pub kid: String,

    /// Timestamp when the recipient was removed (RFC 3339)
    pub removed_at: String,
}

/// Validate wrap items against shared structural constraints.
pub fn validate_wrap_items(wrap_items: &[WrapItem], context: &str) -> Result<()> {
    validate_wrap_count(wrap_items.len(), context)?;

    let mut seen_recipient_handles = HashSet::new();
    for item in wrap_items {
        if !seen_recipient_handles.insert(item.recipient_handle.as_str()) {
            return Err(Error::Verify {
                rule: "E_DUPLICATE_RECIPIENT_HANDLE".to_string(),
                message: format!(
                    "{} contains duplicate recipient_handle '{}' in wrap",
                    context, item.recipient_handle
                ),
            });
        }
    }

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
/// ```
/// use secretenv::model::common::normalize_recipients;
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
