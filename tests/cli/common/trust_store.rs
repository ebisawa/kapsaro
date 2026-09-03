// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Local trust store fixtures for CLI integration tests.
// Writes a store signed by the owner's active key so trust-gated commands have one to read.

use kapsaro_core::test_support::domain::trust_store::{
    KnownKey, RecipientSetRecord, TrustStoreProtected,
};
use kapsaro_core::test_support::domain::wire::format::LOCAL_TRUST_V1;
use kapsaro_core::test_support::operations::trust::signature::sign_trust_store;
use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;
use kapsaro_core::test_support::storage::trust::store::save_trust_store;
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::workspace_state::member_handle;
use tempfile::TempDir;

pub const TRUST_STORE_STORED_AT: &str = "2026-03-29T12:34:56Z";

/// Write a trust store for one owner, signed by that owner's active key.
///
/// The signing kid is returned so a test that later rotates the active key can
/// name the signature the stored document started with.
pub fn save_trust_store_signed_by_active_key(
    home: &TempDir,
    owner_handle: &str,
    known_keys: Vec<KnownKey>,
    recipient_sets: Vec<RecipientSetRecord>,
) -> String {
    let key_ctx = setup_member_key_context(home, owner_handle, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: TRUST_STORE_STORED_AT.to_string(),
        updated_at: TRUST_STORE_STORED_AT.to_string(),
        known_keys,
        recipient_sets,
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home.path(), &member_handle(owner_handle));
    save_trust_store(&path, &document).unwrap();
    key_ctx.kid().to_string()
}
