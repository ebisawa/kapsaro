// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::trust_store::{RecipientHandleHint, RecipientSetRecord};
use crate::service::trust::approval::{
    observe_recipient_set_approval_store, save_known_key_approvals,
    save_reviewed_recipient_set_approval, ApprovedKnownKey,
};
use crate::service::trust::TrustApprovalCandidateBuilder;
use crate::service_test_utils::{
    build_test_command_options, build_test_trust_command_session, load_test_trust_store,
    save_trust_store_signed_by_active_key,
};
#[cfg(unix)]
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::setup_test_keystore_from_fixtures;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
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

#[cfg(unix)]
fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::metadata(source).unwrap().permissions()).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[cfg(unix)]
fn replace_trust_directory_with_snapshot(home: &Path) -> Vec<u8> {
    let trust_dir = home.join("trust");
    let original_dir = home.join("trust.original");
    fs::rename(&trust_dir, &original_dir).unwrap();
    copy_directory(&original_dir, &trust_dir);
    fs::read(trust_dir.join(format!("{ALICE_MEMBER_HANDLE}.json"))).unwrap()
}

#[cfg(unix)]
fn restore_original_trust_directory(home: &Path) {
    fs::rename(home.join("trust"), home.join("trust.replacement")).unwrap();
    fs::rename(home.join("trust.original"), home.join("trust")).unwrap();
}

fn recipient_set(recipient_kids: &[&str]) -> ArtifactRecipientSet {
    ArtifactRecipientSet::from_parts(
        Uuid::parse_str(SID).unwrap(),
        recipient_kids.iter().map(|kid| kid.to_string()).collect(),
        recipient_kids
            .iter()
            .enumerate()
            .map(|(index, kid)| RecipientHandleHint {
                kid: kid.to_string(),
                recipient_handle: format!("recipient-{index}@example.com"),
            })
            .collect(),
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
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let candidate = ApprovedKnownKey::for_test(
        ALICE_MEMBER_HANDLE,
        execution.key_ctx().inner().kid(),
        None,
        None,
    );

    let result = save_known_key_approvals(&execution, &[candidate]);

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
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let candidate = ApprovedKnownKey::for_test(BOB_MEMBER_HANDLE, BOB_KID, None, None);

    save_known_key_approvals(&execution, &[candidate]).unwrap();

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

#[cfg(unix)]
#[test]
fn test_save_known_key_approvals_keeps_opened_trust_directory() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_trust_store_signed_by_active_key(
        &home,
        ALICE_MEMBER_HANDLE,
        STORED_AT,
        Vec::new(),
        Vec::new(),
    );
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let candidate = ApprovedKnownKey::for_test(BOB_MEMBER_HANDLE, BOB_KID, None, None);
    execution.ensured_trust_directory().unwrap();
    let replacement_snapshot = replace_trust_directory_with_snapshot(home.path());

    save_known_key_approvals(&execution, &[candidate]).unwrap();

    let replacement_path = home
        .path()
        .join("trust")
        .join(format!("{ALICE_MEMBER_HANDLE}.json"));
    assert_eq!(fs::read(replacement_path).unwrap(), replacement_snapshot);
    restore_original_trust_directory(home.path());
    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the opened trust directory must receive the approval");
    assert_eq!(stored.protected.known_keys.len(), 1);
    assert_eq!(stored.protected.known_keys[0].kid, BOB_KID);
}

#[cfg(unix)]
#[test]
fn test_save_known_key_approvals_returns_operation_warnings_to_command_sink() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let candidate = ApprovedKnownKey::for_test(BOB_MEMBER_HANDLE, BOB_KID, None, None);
    save_known_key_approvals(&execution, std::slice::from_ref(&candidate)).unwrap();
    let trust_dir = home.path().join("trust");
    fs::set_permissions(&trust_dir, fs::Permissions::from_mode(0o755))
        .expect("make trust directory observable by other users");
    let warning_guard = LocalStateWarningGuard::new();

    save_known_key_approvals(&execution, &[candidate]).unwrap();

    assert!(warning_guard
        .take()
        .warnings
        .iter()
        .any(|warning| warning.path() == trust_dir));
}

#[test]
fn test_save_known_key_approvals_persists_verified_github_evidence() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let verified_github =
        VerifiedGithubIdentity::new(42, "octocat".to_string(), "SHA256:fp".to_string(), 100);
    let candidate =
        ApprovedKnownKey::for_test(BOB_MEMBER_HANDLE, BOB_KID, None, Some(&verified_github));

    save_known_key_approvals(&execution, &[candidate]).unwrap();

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
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let service_candidate = crate::service::trust::KnownKeyReviewCandidate::for_test(
        BOB_MEMBER_HANDLE,
        BOB_KID,
        "ssh-ed25519 AAAA test",
    );
    let candidate =
        TrustApprovalCandidateBuilder::from_known_key_candidate(&service_candidate).build();
    let approval = ApprovedKnownKey::from_candidate(&candidate).unwrap();

    save_known_key_approvals(&execution, &[approval]).unwrap();

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
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let service_candidate =
        crate::service::trust::KnownKeyReviewCandidate::for_test_with_github_binding(
            BOB_MEMBER_HANDLE,
            BOB_KID,
            "ssh-ed25519 AAAA test",
            true,
        );
    let evidence = crate::service::online::VerifiedGitHubEvidence::for_test(
        &service_candidate,
        42,
        "octocat",
        "SHA256:fp",
        100,
    );
    let candidate = TrustApprovalCandidateBuilder::from_known_key_candidate(&service_candidate)
        .with_verified_service_evidence(evidence)
        .build();
    let approval = ApprovedKnownKey::from_candidate(&candidate).unwrap();

    save_known_key_approvals(&execution, &[approval]).unwrap();

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
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);

    let observed = observe_recipient_set_approval_store(&execution).unwrap();
    save_reviewed_recipient_set_approval(
        &execution,
        observed.as_ref(),
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

#[cfg(unix)]
#[test]
fn test_save_recipient_set_approval_keeps_opened_trust_directory() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_trust_store_signed_by_active_key(
        &home,
        ALICE_MEMBER_HANDLE,
        STORED_AT,
        Vec::new(),
        Vec::new(),
    );
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let observed = observe_recipient_set_approval_store(&execution).unwrap();
    let replacement_snapshot = replace_trust_directory_with_snapshot(home.path());

    save_reviewed_recipient_set_approval(
        &execution,
        observed.as_ref(),
        recipient_set(&[RECIPIENT_A_KID, RECIPIENT_B_KID]),
    )
    .unwrap();

    let replacement_path = home
        .path()
        .join("trust")
        .join(format!("{ALICE_MEMBER_HANDLE}.json"));
    assert_eq!(fs::read(replacement_path).unwrap(), replacement_snapshot);
    restore_original_trust_directory(home.path());
    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the opened trust directory must receive the approval");
    assert_eq!(stored.protected.recipient_sets.len(), 1);
    assert_eq!(stored.protected.recipient_sets[0].sid, SID);
}

#[cfg(unix)]
#[test]
fn test_save_recipient_set_approval_returns_operation_warnings_to_command_sink() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let observed = observe_recipient_set_approval_store(&execution).unwrap();
    save_reviewed_recipient_set_approval(
        &execution,
        observed.as_ref(),
        recipient_set(&[RECIPIENT_A_KID]),
    )
    .unwrap();
    let observed = observe_recipient_set_approval_store(&execution).unwrap();
    let trust_dir = home.path().join("trust");
    fs::set_permissions(&trust_dir, fs::Permissions::from_mode(0o755))
        .expect("make trust directory observable by other users");
    let warning_guard = LocalStateWarningGuard::new();

    save_reviewed_recipient_set_approval(
        &execution,
        observed.as_ref(),
        recipient_set(&[RECIPIENT_A_KID, RECIPIENT_B_KID]),
    )
    .unwrap();

    assert!(warning_guard
        .take()
        .warnings
        .iter()
        .any(|warning| warning.path() == trust_dir));
}

/// A recipient-set approval replaces the whole record its sid names, so it is
/// bound to the document it was written against. Another run that approved a
/// smaller set for the same artifact left a record this operator never looked
/// at, and writing the reviewed one over it would put the recipient that run
/// dropped back into the approved set.
#[test]
fn test_save_recipient_set_approval_refuses_a_store_that_moved_after_it_was_observed() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_trust_store_signed_by_active_key(
        &home,
        ALICE_MEMBER_HANDLE,
        STORED_AT,
        Vec::new(),
        Vec::new(),
    );
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_trust_command_session(&home, ALICE_MEMBER_HANDLE);
    let committed = recipient_set_record(&[RECIPIENT_A_KID, RECIPIENT_B_KID]);

    let observed = observe_recipient_set_approval_store(&execution).unwrap();
    save_trust_store_signed_by_active_key(
        &home,
        ALICE_MEMBER_HANDLE,
        STORED_AT,
        Vec::new(),
        vec![committed.clone()],
    );

    let error = save_reviewed_recipient_set_approval(
        &execution,
        observed.as_ref(),
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
