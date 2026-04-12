// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::trust::list::list_known_keys;
use crate::app_test_utils::build_test_command_options;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::trust::paths::trust_store_file_path;
use crate::io::trust::store::save_trust_store;
use crate::model::identifiers::format::TRUST_LOCAL_V2;
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use tempfile::TempDir;

const KID_BOB: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const KID_CHARLIE: &str = "C4AR1E00C4AR1E00C4AR1E00C4AR1E00";
const ALICE_MEMBER_ID: &str = "alice@example.com";

fn make_known_key(kid: &str, member_id: &str, approved_at: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        member_id: member_id.to_string(),
        approved_at: approved_at.to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn save_signed_trust_store(home: &TempDir) {
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_ID, None);
    let protected = TrustStoreProtected {
        format: TRUST_LOCAL_V2.to_string(),
        owner_member_id: ALICE_MEMBER_ID.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![
            make_known_key(KID_BOB, "bob@example.com", "2026-03-29T12:40:00Z"),
            make_known_key(KID_CHARLIE, "charlie@example.com", "2026-03-29T12:41:00Z"),
        ],
    };
    let document = sign_trust_store(&protected, &key_ctx.signing_key, &key_ctx.kid).unwrap();
    let path = trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    save_trust_store(&path, &document).unwrap();
}

#[test]
fn test_list_known_keys_succeeds_without_ssh_signing_method() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    let options = build_test_command_options(home.path(), None);
    let result = list_known_keys(&options, ALICE_MEMBER_ID).unwrap();

    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].kid, KID_BOB);
    assert_eq!(result.items[1].kid, KID_CHARLIE);
}
