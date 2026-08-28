// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store setup and readback for application-layer tests.
//! Opens the local state directory a test named and verifies the stored document.

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::load_optional_trust_store;
use crate::cli_api::test_support::storage::trust::store::save_trust_store;
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::store_mutation::TrustStoreState;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::identity::MemberHandle;
use crate::model::trust_store::{RecipientSetRecord, TrustStoreProtected};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, DirectoryScope};
use crate::test_utils::{member_handle, setup_member_key_context};
use crate::Result;
use tempfile::TempDir;

/// Read back the trust store a command wrote under one local state directory.
pub(crate) fn load_test_trust_store(
    options: &CommonCommandOptions,
    owner_handle: &str,
) -> Result<Option<TrustStoreState>> {
    let base = AnchoredDir::open(
        options.resolve_base_dir()?,
        DirectoryScope::LocalState,
        "test local state root",
    )?;
    let trust_dir = open_optional_child_dir(&base, "trust")?;
    let owner = MemberHandle::try_from(owner_handle)?;
    load_optional_trust_store(&base, trust_dir.as_ref(), &owner, None)
}

/// Write an empty trust store signed by the owner's currently active key.
///
/// The signing kid is returned so a test that later rotates the active key can
/// state which signature the stored document started with.
pub(crate) fn save_test_trust_store_signed_by_active_key(
    home: &TempDir,
    owner_handle: &str,
    stored_at: &str,
) -> String {
    save_test_trust_store_with_recipient_sets(home, owner_handle, stored_at, Vec::new())
}

/// Write a trust store carrying `recipient_sets`, signed by the active key.
///
/// This is what another run committing its own approval leaves behind: the
/// document verifies, and the records it holds are not the ones the caller
/// under test reviewed.
pub(crate) fn save_test_trust_store_with_recipient_sets(
    home: &TempDir,
    owner_handle: &str,
    stored_at: &str,
    recipient_sets: Vec<RecipientSetRecord>,
) -> String {
    let key_ctx = setup_member_key_context(home, owner_handle, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: stored_at.to_string(),
        updated_at: stored_at.to_string(),
        known_keys: Vec::new(),
        recipient_sets,
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home.path(), &member_handle(owner_handle));
    save_trust_store(&path, &document).unwrap();
    key_ctx.kid().to_string()
}
