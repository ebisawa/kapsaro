// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Local trust store fixtures shared by every test binary.
//! Builds the records a store holds and writes one signed by the owner's active key.

use kapsaro_core::test_support::domain::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientSetApprovalVia, RecipientSetRecord, TrustStoreProtected,
};
use kapsaro_core::test_support::domain::wire::format::LOCAL_TRUST_V1;
use kapsaro_core::test_support::operations::context::crypto::CryptoContext;
use kapsaro_core::test_support::operations::trust::recipient_sets::compute_recipient_set_hash;
use kapsaro_core::test_support::operations::trust::signature::sign_trust_store;
use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
use kapsaro_core::test_support::storage::trust::store::save_trust_store;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::TempDir;

use super::crypto_context::setup_member_key_context;
use super::workspace_state::member_handle;

/// Approval timestamp a known-key fixture carries when the test does not pin one.
const DEFAULT_KNOWN_KEY_APPROVED_AT: &str = "2026-03-29T12:40:00Z";

/// Build one manually approved known-key record.
///
/// `approved_at` is what a test that orders or purges records by time pins; the
/// tests that only need a record present leave it out.
pub fn build_known_key(kid: &str, subject_handle: &str, approved_at: Option<&str>) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        subject_handle: subject_handle.to_string(),
        approved_at: approved_at
            .unwrap_or(DEFAULT_KNOWN_KEY_APPROVED_AT)
            .to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

/// Build one manually approved recipient-set record for an artifact.
///
/// The hash is computed from the kids rather than passed in, so a fixture
/// cannot state a set and a hash that disagree.
pub fn build_recipient_set(
    sid: &str,
    recipient_kids: &[&str],
    approved_at: &str,
) -> RecipientSetRecord {
    let recipient_kids = recipient_kids
        .iter()
        .map(|kid| (*kid).to_string())
        .collect::<Vec<_>>();
    RecipientSetRecord {
        sid: sid.to_string(),
        recipient_set_hash: compute_recipient_set_hash(&recipient_kids).unwrap(),
        recipient_kids,
        approved_at: approved_at.to_string(),
        approved_via: RecipientSetApprovalVia::ManualReview,
        recipient_handle_hints: None,
    }
}

/// Write a trust store for one owner, signed by that owner's active key.
///
/// The signing kid is returned so a test that later rotates the active key can
/// name the signature the stored document started with.
pub fn save_trust_store_signed_by_active_key(
    home: &TempDir,
    owner_handle: &str,
    stored_at: &str,
    known_keys: Vec<KnownKey>,
    recipient_sets: Vec<RecipientSetRecord>,
) -> String {
    let key_ctx = setup_member_key_context(home, owner_handle, None);
    save_trust_store_signed_by_key_context(
        home.path(),
        owner_handle,
        stored_at,
        known_keys,
        recipient_sets,
        &key_ctx,
    );
    key_ctx.kid().to_string()
}

/// Write a trust store signed by a key context the caller already opened.
///
/// A workspace fixture holds its own context because it also reads the members
/// it approves, so the document it writes is built here rather than assembled a
/// second time.
pub fn save_trust_store_signed_by_key_context(
    home: &Path,
    owner_handle: &str,
    stored_at: &str,
    known_keys: Vec<KnownKey>,
    recipient_sets: Vec<RecipientSetRecord>,
    key_ctx: &CryptoContext,
) {
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: stored_at.to_string(),
        updated_at: stored_at.to_string(),
        known_keys,
        recipient_sets,
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home, &member_handle(owner_handle));
    save_trust_store(&path, &document).unwrap();
}
