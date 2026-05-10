// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::trust::list::{list_known_keys, list_recipient_sets};
use crate::app_test_utils::build_test_command_options;
use crate::feature::trust::recipient_sets::compute_recipient_set_hash;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::save_trust_store;
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientSetApprovalVia, RecipientSetRecord, TrustStoreProtected,
};
use crate::model::wire::format::LOCAL_TRUST_V5;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use tempfile::TempDir;

const KID_BOB: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const KID_CHARLIE: &str = "C4AR1E00C4AR1E00C4AR1E00C4AR1E00";
const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const SID_ENV_FILE: &str = "00000000-0000-4000-8000-000000000101";

fn build_known_key(kid: &str, member_handle: &str, approved_at: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        subject_handle: member_handle.to_string(),
        approved_at: approved_at.to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn build_recipient_set(
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

fn save_signed_trust_store(home: &TempDir) {
    save_signed_trust_store_with_recipient_sets(home, Vec::new());
}

fn save_signed_trust_store_with_recipient_sets(
    home: &TempDir,
    recipient_sets: Vec<RecipientSetRecord>,
) {
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V5.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![
            build_known_key(KID_BOB, "bob@example.com", "2026-03-29T12:40:00Z"),
            build_known_key(KID_CHARLIE, "charlie@example.com", "2026-03-29T12:41:00Z"),
        ],
        recipient_sets,
    };
    let document = sign_trust_store(&protected, &key_ctx.signing_key, &key_ctx.kid).unwrap();
    let path = get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE);
    save_trust_store(&path, &document).unwrap();
}

#[test]
fn test_list_known_keys_succeeds_without_ssh_signing_method() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    let options = build_test_command_options(home.path(), None);
    let result = list_known_keys(&options, ALICE_MEMBER_HANDLE).unwrap();

    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].kid, KID_BOB);
    assert_eq!(result.items[1].kid, KID_CHARLIE);
}

#[test]
fn test_list_recipient_sets_returns_empty_when_store_is_missing() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);

    let result = list_recipient_sets(&options, ALICE_MEMBER_HANDLE).unwrap();

    assert!(result.items.is_empty());
    assert!(result.warnings.is_empty());
}

#[test]
fn test_list_recipient_sets_preserves_signed_store_fields() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let recipient_set = build_recipient_set(
        SID_ENV_FILE,
        &[KID_BOB, KID_CHARLIE],
        "2026-03-29T12:42:00Z",
    );
    let expected_hash = recipient_set.recipient_set_hash.clone();
    save_signed_trust_store_with_recipient_sets(&home, vec![recipient_set]);
    let options = build_test_command_options(home.path(), None);

    let result = list_recipient_sets(&options, ALICE_MEMBER_HANDLE).unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sid, SID_ENV_FILE);
    assert_eq!(result.items[0].recipient_set_hash, expected_hash);
    assert_eq!(
        result.items[0].recipient_kids,
        vec![KID_BOB.to_string(), KID_CHARLIE.to_string()]
    );
}
