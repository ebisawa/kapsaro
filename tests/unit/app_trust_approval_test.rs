// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::app::trust::TrustApprovalCandidate;
use crate::app_test_utils::{build_test_command_options, build_test_execution_context};
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::load_trust_store;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::test_utils::{kid, member_id, setup_test_keystore_from_fixtures};

const ALICE_MEMBER_ID: &str = "alice@example.com";
const BOB_MEMBER_ID: &str = "bob@example.com";
const BOB_KID: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";

#[test]
fn test_save_known_key_approvals_rejects_self_candidate() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    let candidate =
        ApprovedKnownKey::from_review(ALICE_MEMBER_ID, &execution.key_ctx.kid, None, None);

    let result = save_known_key_approvals(&options, &execution, &[candidate]);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("must not be stored in known_keys"));
    let trust_path = get_trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    assert!(load_trust_store(&trust_path, home.path())
        .unwrap()
        .is_none());
}

#[test]
fn test_save_known_key_approvals_uses_execution_context_for_signing() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    let candidate = ApprovedKnownKey::from_review(BOB_MEMBER_ID, BOB_KID, None, None);

    save_known_key_approvals(&options, &execution, &[candidate]).unwrap();

    let trust_path = get_trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, home.path()).unwrap().unwrap();
    let stored = serde_json::to_value(&loaded.document).unwrap();
    assert_eq!(
        stored["protected"]["owner_member_id"],
        serde_json::json!(ALICE_MEMBER_ID)
    );
    assert_eq!(
        stored["protected"]["known_keys"][0]["member_id"],
        serde_json::json!(BOB_MEMBER_ID)
    );
}

#[test]
fn test_save_known_key_approvals_persists_verified_github_evidence() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    let verified_github =
        VerifiedGithubIdentity::new(42, "octocat".to_string(), "SHA256:fp".to_string(), 100);
    let candidate =
        ApprovedKnownKey::from_review(BOB_MEMBER_ID, BOB_KID, None, Some(&verified_github));

    save_known_key_approvals(&options, &execution, &[candidate]).unwrap();

    let trust_path = get_trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, home.path()).unwrap().unwrap();
    let stored = serde_json::to_value(&loaded.document).unwrap();
    let github_account = &stored["protected"]["known_keys"][0]["evidence"]["github_account"];
    assert_eq!(github_account["id"], serde_json::json!(42));
    assert_eq!(github_account["login"], serde_json::json!("octocat"));
}

#[test]
fn test_save_known_key_approvals_does_not_persist_raw_github_claim_from_manual_review() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    let candidate = TrustApprovalCandidate {
        member_id: member_id(BOB_MEMBER_ID),
        kid: kid(BOB_KID),
        fingerprint: Some("SHA256:fp".to_string()),
        github_id: Some(42),
        github_login: Some("raw-claim".to_string()),
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: true,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: true,
    };
    let approval = ApprovedKnownKey::from_review(
        &candidate.member_id,
        &candidate.kid,
        candidate.attestor_pub.clone(),
        None,
    );

    save_known_key_approvals(&options, &execution, &[approval]).unwrap();

    let trust_path = get_trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, home.path()).unwrap().unwrap();
    let stored = serde_json::to_value(&loaded.document).unwrap();
    let evidence = &stored["protected"]["known_keys"][0]["evidence"];
    assert!(evidence.get("github_account").is_none());
    assert_eq!(
        evidence["ssh_attestor_pub"],
        serde_json::json!("ssh-ed25519 AAAA test")
    );
}

#[test]
fn test_save_known_key_approvals_persists_verified_github_from_trust_review_candidate() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_ID, None);
    let verified_github =
        VerifiedGithubIdentity::new(42, "octocat".to_string(), "SHA256:fp".to_string(), 100);
    let candidate = TrustApprovalCandidate {
        member_id: member_id(BOB_MEMBER_ID),
        kid: kid(BOB_KID),
        fingerprint: Some("SHA256:fp".to_string()),
        github_id: Some(42),
        github_login: Some("octocat".to_string()),
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: Some(verified_github),
        github_binding_configured: true,
        online_verification_attempted: true,
        online_verification_message: Some("verified".to_string()),
        public_key: None,
        requires_out_of_band_verification: true,
    };
    let approval = ApprovedKnownKey::from(&candidate);

    save_known_key_approvals(&options, &execution, &[approval]).unwrap();

    let trust_path = get_trust_store_file_path(home.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, home.path()).unwrap().unwrap();
    let stored = serde_json::to_value(&loaded.document).unwrap();
    let github_account = &stored["protected"]["known_keys"][0]["evidence"]["github_account"];
    assert_eq!(github_account["id"], serde_json::json!(42));
    assert_eq!(github_account["login"], serde_json::json!("octocat"));
}
