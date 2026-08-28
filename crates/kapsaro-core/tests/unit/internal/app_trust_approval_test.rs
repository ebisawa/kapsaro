// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::approval::{
    observe_recipient_set_approval_store, save_known_key_approvals,
    save_reviewed_recipient_set_approval, ApprovedKnownKey,
};
use crate::app::trust::TrustApprovalCandidate;
use crate::app_test_utils::{
    build_test_command_options, build_test_execution_context, load_test_trust_store,
    save_test_trust_store_signed_by_active_key, save_test_trust_store_with_recipient_sets,
};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::trust_store::RecipientSetRecord;
use crate::test_utils::{kid, member_handle, setup_test_keystore_from_fixtures};
use uuid::Uuid;

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";
const BOB_KID: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
/// Artifact the two runs below both approve a recipient set for.
const SID: &str = "3f1b2c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const RECIPIENT_A_KID: &str = "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0";
const RECIPIENT_B_KID: &str = "B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1";
/// Recipient the other run dropped from the artifact.
const RECIPIENT_C_KID: &str = "C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0";
const STORED_AT: &str = "2026-03-29T12:34:56Z";

fn recipient_set(recipient_kids: &[&str]) -> ArtifactRecipientSet {
    ArtifactRecipientSet::new(
        Uuid::parse_str(SID).unwrap(),
        recipient_kids.iter().map(|kid| kid.to_string()).collect(),
    )
    .unwrap()
}

fn recipient_set_record(recipient_kids: &[&str]) -> RecipientSetRecord {
    recipient_set(recipient_kids).into_record(STORED_AT.to_string())
}

#[test]
fn test_save_known_key_approvals_rejects_self_candidate() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let candidate =
        ApprovedKnownKey::from_review(ALICE_MEMBER_HANDLE, execution.key_ctx.kid(), None, None);

    let result = save_known_key_approvals(&options, &execution, &[candidate]);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("must not be stored in known_keys"));
    assert!(load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .is_none());
}

#[test]
fn test_save_known_key_approvals_uses_execution_context_for_signing() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let candidate = ApprovedKnownKey::from_review(BOB_MEMBER_HANDLE, BOB_KID, None, None);

    save_known_key_approvals(&options, &execution, &[candidate]).unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let stored = serde_json::to_value(&loaded.protected).unwrap();
    assert_eq!(
        stored["owner_handle"],
        serde_json::json!(ALICE_MEMBER_HANDLE)
    );
    assert_eq!(
        stored["known_keys"][0]["subject_handle"],
        serde_json::json!(BOB_MEMBER_HANDLE)
    );
}

#[test]
fn test_save_known_key_approvals_persists_verified_github_evidence() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let verified_github =
        VerifiedGithubIdentity::new(42, "octocat".to_string(), "SHA256:fp".to_string(), 100);
    let candidate =
        ApprovedKnownKey::from_review(BOB_MEMBER_HANDLE, BOB_KID, None, Some(&verified_github));

    save_known_key_approvals(&options, &execution, &[candidate]).unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let stored = serde_json::to_value(&loaded.protected).unwrap();
    let github_account = &stored["known_keys"][0]["evidence"]["github_account"];
    assert_eq!(github_account["id"], serde_json::json!(42));
    assert_eq!(github_account["login"], serde_json::json!("octocat"));
}

#[test]
fn test_save_known_key_approvals_records_manual_review_without_a_github_claim() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle(BOB_MEMBER_HANDLE),
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
        &candidate.member_handle,
        &candidate.kid,
        candidate.attestor_pub.clone(),
        None,
    );

    save_known_key_approvals(&options, &execution, &[approval]).unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let stored = serde_json::to_value(&loaded.protected).unwrap();
    let evidence = &stored["known_keys"][0]["evidence"];
    assert!(evidence.get("github_account").is_none());
    assert_eq!(
        evidence["ssh_attestor_pub"],
        serde_json::json!("ssh-ed25519 AAAA test")
    );
}

#[test]
fn test_save_known_key_approvals_persists_verified_github_from_trust_review_candidate() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let verified_github =
        VerifiedGithubIdentity::new(42, "octocat".to_string(), "SHA256:fp".to_string(), 100);
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle(BOB_MEMBER_HANDLE),
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

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let stored = serde_json::to_value(&loaded.protected).unwrap();
    let github_account = &stored["known_keys"][0]["evidence"]["github_account"];
    assert_eq!(github_account["id"], serde_json::json!(42));
    assert_eq!(github_account["login"], serde_json::json!("octocat"));
}

/// The recipient set the operator agreed to is the one the store ends up
/// holding, created alongside the store on the first approval.
#[test]
fn test_save_recipient_set_approval_stores_the_reviewed_recipient_set() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let observed = observe_recipient_set_approval_store(&execution).unwrap();
    save_reviewed_recipient_set_approval(
        &execution,
        &observed,
        recipient_set(&[RECIPIENT_A_KID, RECIPIENT_B_KID]),
    )
    .unwrap();

    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the approval must be stored");
    let [record] = stored.protected.recipient_sets.as_slice() else {
        panic!("one approval stores one recipient set record");
    };
    assert_eq!(record.sid, SID);
    assert_eq!(
        record.recipient_kids,
        vec![RECIPIENT_A_KID.to_string(), RECIPIENT_B_KID.to_string()]
    );
}

/// A recipient-set approval replaces the whole record its sid names, so it is
/// bound to the document it was written against. Another run that approved a
/// smaller set for the same artifact left a record this operator never looked
/// at, and writing the reviewed one over it would put the recipient that run
/// dropped back into the approved set.
#[test]
fn test_save_recipient_set_approval_refuses_a_store_that_moved_after_it_was_observed() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_test_trust_store_signed_by_active_key(&home, ALICE_MEMBER_HANDLE, STORED_AT);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let committed = recipient_set_record(&[RECIPIENT_A_KID, RECIPIENT_B_KID]);

    let observed = observe_recipient_set_approval_store(&execution).unwrap();
    save_test_trust_store_with_recipient_sets(
        &home,
        ALICE_MEMBER_HANDLE,
        STORED_AT,
        vec![committed.clone()],
    );

    let error = save_reviewed_recipient_set_approval(
        &execution,
        &observed,
        recipient_set(&[RECIPIENT_A_KID, RECIPIENT_B_KID, RECIPIENT_C_KID]),
    )
    .expect_err("an approval written against content that moved must be refused");

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(
        error
            .format_user_message()
            .contains("Run the command again"),
        "got: {}",
        error.format_user_message()
    );
    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the other run's approval must still be there");
    assert_eq!(stored.protected.recipient_sets, vec![committed]);
}
