// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::trust::management::{
    execute_purge, list_purge_candidates, remove_known_key_command,
};
use crate::app_test_utils::{build_test_command_options, build_test_execution_context};
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::verification::verify_trust_store;
use crate::io::trust::paths::trust_store_file_path;
use crate::io::trust::store::{load_trust_store, save_trust_store};
use crate::model::identifiers::format::TRUST_LOCAL_V2;
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const KID_OLD: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const KID_FRACTIONAL: &str = "C4AR1E00C4AR1E00C4AR1E00C4AR1E00";
const KID_NEW: &str = "D4VE0000D4VE0000D4VE0000D4VE0000";
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

fn parse_timestamp(ts: &str) -> OffsetDateTime {
    OffsetDateTime::parse(ts, &Rfc3339).unwrap()
}

fn save_signed_trust_store(home: &TempDir) {
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_ID, None);
    let protected = TrustStoreProtected {
        format: TRUST_LOCAL_V2.to_string(),
        owner_member_id: ALICE_MEMBER_ID.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![
            make_known_key(KID_OLD, "bob@example.com", "2026-01-01T00:00:00Z"),
            make_known_key(
                KID_FRACTIONAL,
                "charlie@example.com",
                "2026-01-01T00:00:00.1Z",
            ),
            make_known_key(KID_NEW, "dave@example.com", "2026-06-01T00:00:00Z"),
        ],
    };
    let document = sign_trust_store(&protected, &key_ctx.signing_key, &key_ctx.kid).unwrap();
    let path = trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    save_trust_store(&path, &document).unwrap();
}

#[test]
fn test_list_purge_candidates_filters_fractional_seconds() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);

    let options = build_test_command_options(home.path(), None);
    let result = list_purge_candidates(
        &options,
        ALICE_MEMBER_ID,
        parse_timestamp("2026-01-01T00:00:01Z"),
    )
    .unwrap();

    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].kid, KID_OLD);
    assert_eq!(result.items[1].kid, KID_FRACTIONAL);
}

#[test]
fn test_remove_known_key_command_rejects_expired_signing_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let mut execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    execution.key_ctx.expires_at = "2020-01-01T00:00:00Z".to_string();

    let result = remove_known_key_command(&options, &execution, KID_OLD, false);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let loaded = load_trust_store(
        &trust_store_file_path(home.path(), ALICE_MEMBER_ID),
        home.path(),
    )
    .unwrap()
    .unwrap();
    let verified = verify_trust_store(&loaded.document, &home.path().join("keys")).unwrap();
    assert!(verified
        .document()
        .protected
        .known_keys
        .iter()
        .any(|entry| entry.kid == KID_OLD));
}

#[test]
fn test_execute_purge_rejects_expired_signing_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let mut execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    execution.key_ctx.expires_at = "2020-01-01T00:00:00Z".to_string();

    let result = execute_purge(
        &options,
        &execution,
        parse_timestamp("2026-01-01T00:00:01Z"),
        false,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let loaded = load_trust_store(
        &trust_store_file_path(home.path(), ALICE_MEMBER_ID),
        home.path(),
    )
    .unwrap()
    .unwrap();
    let verified = verify_trust_store(&loaded.document, &home.path().join("keys")).unwrap();
    assert_eq!(verified.document().protected.known_keys.len(), 3);
}

#[cfg(unix)]
#[test]
fn test_remove_known_key_command_surfaces_insecure_permission_warning() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    let trust_path = trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let result = remove_known_key_command(&options, &execution, KID_OLD, false).unwrap();

    assert_eq!(result.value, "bob@example.com");
    assert!(!result.warnings.is_empty());
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("Insecure permissions")));
}
