// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::app::member::approval::{
    evaluate_members_for_approval, save_member_approvals, MemberApprovalResult,
};
use crate::app_test_utils::{build_test_command_options, build_test_execution_context};
use crate::test_utils::setup_test_workspace_from_fixtures;
use crate::{
    feature::trust::verification::verify_trust_store, io::trust::paths::get_trust_store_file_path,
    io::trust::store::load_trust_store, io::verify_online::VerifiedGithubIdentity,
    io::workspace::members::load_active_member_files, model::public_key::PublicKey,
};

const ALICE_MEMBER_ID: &str = "alice@example.com";
const BOB_MEMBER_ID: &str = "bob@example.com";

fn find_kid(active_members: &[PublicKey], member_id: &str) -> String {
    active_members
        .iter()
        .find(|pk| pk.protected.member_id == member_id)
        .map(|pk| pk.protected.kid.clone())
        .unwrap()
}

fn find_member(active_members: &[PublicKey], member_id: &str) -> PublicKey {
    active_members
        .iter()
        .find(|pk| pk.protected.member_id == member_id)
        .cloned()
        .unwrap()
}

#[test]
fn test_save_member_approvals_persists_only_manually_approved_candidates() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob_kid = find_kid(&active_members, BOB_MEMBER_ID);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution = build_test_execution_context(&temp_dir, ALICE_MEMBER_ID, Some(&workspace_dir));

    save_member_approvals(
        &options,
        &[MemberApprovalResult {
            member_id: BOB_MEMBER_ID.to_string(),
            kid: bob_kid.clone(),
            verified: false,
            approved: true,
            review_required: true,
            already_known: false,
            message: "manual review".to_string(),
            fingerprint: None,
            github_id: None,
            github_login: None,
            github_binding_configured: false,
            attestor_pub: Some(
                find_member(&active_members, BOB_MEMBER_ID)
                    .protected
                    .identity
                    .attestation
                    .pub_,
            ),
            verified_github: None,
        }],
        &execution,
    )
    .unwrap();

    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .unwrap();
    let verified = verify_trust_store(&loaded.document, &temp_dir.path().join("keys")).unwrap();
    assert!(verified
        .document()
        .protected
        .known_keys
        .iter()
        .any(|entry| entry.member_id == BOB_MEMBER_ID && entry.kid == bob_kid));
}

#[test]
fn test_save_member_approvals_rejects_expired_signing_key() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob_kid = find_kid(&active_members, BOB_MEMBER_ID);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    crate::test_utils::update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_ID,
        "2020-01-01T00:00:00Z",
    );
    let execution = build_test_execution_context(&temp_dir, ALICE_MEMBER_ID, Some(&workspace_dir));

    let result = save_member_approvals(
        &options,
        &[MemberApprovalResult {
            member_id: BOB_MEMBER_ID.to_string(),
            kid: bob_kid,
            verified: false,
            approved: true,
            review_required: true,
            already_known: false,
            message: "manual review".to_string(),
            fingerprint: None,
            github_id: None,
            github_login: None,
            github_binding_configured: false,
            attestor_pub: Some(
                find_member(&active_members, BOB_MEMBER_ID)
                    .protected
                    .identity
                    .attestation
                    .pub_,
            ),
            verified_github: None,
        }],
        &execution,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    assert!(load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .is_none());
}

#[test]
fn test_save_member_approvals_rejects_self_member() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let alice = find_member(&active_members, ALICE_MEMBER_ID);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution = build_test_execution_context(&temp_dir, ALICE_MEMBER_ID, Some(&workspace_dir));

    let result = save_member_approvals(
        &options,
        &[MemberApprovalResult {
            member_id: ALICE_MEMBER_ID.to_string(),
            kid: alice.protected.kid.clone(),
            verified: true,
            approved: true,
            review_required: false,
            already_known: false,
            message: "self".to_string(),
            fingerprint: None,
            github_id: None,
            github_login: None,
            github_binding_configured: false,
            attestor_pub: Some(alice.protected.identity.attestation.pub_.clone()),
            verified_github: None,
        }],
        &execution,
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("must not be stored in known_keys"));
}

#[test]
fn test_save_member_approvals_uses_evaluated_snapshot_without_rereading_workspace() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_ID);
    let original_attestor_pub = bob.protected.identity.attestation.pub_.clone();
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution = build_test_execution_context(&temp_dir, ALICE_MEMBER_ID, Some(&workspace_dir));
    let bob_file = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let mut tampered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bob_file).unwrap()).unwrap();
    tampered["protected"]["identity"]["attestation"]["pub"] =
        serde_json::Value::String("ssh-ed25519 AAAA changed".to_string());
    fs::write(&bob_file, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

    save_member_approvals(
        &options,
        &[MemberApprovalResult {
            member_id: BOB_MEMBER_ID.to_string(),
            kid: bob.protected.kid.clone(),
            verified: true,
            approved: true,
            review_required: true,
            already_known: false,
            message: "manual review".to_string(),
            fingerprint: None,
            github_id: None,
            github_login: None,
            github_binding_configured: false,
            attestor_pub: Some(original_attestor_pub.clone()),
            verified_github: None,
        }],
        &execution,
    )
    .unwrap();

    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .unwrap();
    let verified = verify_trust_store(&loaded.document, &temp_dir.path().join("keys")).unwrap();
    let saved = verified
        .document()
        .protected
        .known_keys
        .iter()
        .find(|entry| entry.member_id == BOB_MEMBER_ID)
        .unwrap();
    assert_eq!(
        saved.evidence.as_ref().unwrap().ssh_attestor_pub.as_deref(),
        Some(original_attestor_pub.as_str())
    );
}

#[test]
fn test_save_member_approvals_persists_verified_github_login_from_review() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_ID);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution = build_test_execution_context(&temp_dir, ALICE_MEMBER_ID, Some(&workspace_dir));

    save_member_approvals(
        &options,
        &[MemberApprovalResult {
            member_id: BOB_MEMBER_ID.to_string(),
            kid: bob.protected.kid.clone(),
            verified: true,
            approved: true,
            review_required: true,
            already_known: false,
            message: "verified".to_string(),
            fingerprint: Some("SHA256:fp".to_string()),
            github_id: Some(42),
            github_login: Some("current-login".to_string()),
            github_binding_configured: true,
            attestor_pub: Some(bob.protected.identity.attestation.pub_.clone()),
            verified_github: Some(VerifiedGithubIdentity::new(
                42,
                "current-login".to_string(),
                "SHA256:fp".to_string(),
                100,
            )),
        }],
        &execution,
    )
    .unwrap();

    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .unwrap();
    let verified = verify_trust_store(&loaded.document, &temp_dir.path().join("keys")).unwrap();
    let saved = verified
        .document()
        .protected
        .known_keys
        .iter()
        .find(|entry| entry.member_id == BOB_MEMBER_ID)
        .unwrap();
    let github = saved
        .evidence
        .as_ref()
        .and_then(|evidence| evidence.github_account.as_ref())
        .unwrap();
    assert_eq!(github.id, 42);
    assert_eq!(github.login.as_deref(), Some("current-login"));
}

#[cfg(unix)]
#[test]
fn test_evaluate_members_for_approval_surfaces_insecure_trust_store_warning() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_ID);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution = build_test_execution_context(&temp_dir, ALICE_MEMBER_ID, Some(&workspace_dir));

    save_member_approvals(
        &options,
        &[MemberApprovalResult {
            member_id: BOB_MEMBER_ID.to_string(),
            kid: bob.protected.kid.clone(),
            verified: true,
            approved: true,
            review_required: true,
            already_known: false,
            message: "manual review".to_string(),
            fingerprint: None,
            github_id: None,
            github_login: None,
            github_binding_configured: false,
            attestor_pub: Some(bob.protected.identity.attestation.pub_.clone()),
            verified_github: None,
        }],
        &execution,
    )
    .unwrap();

    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let evaluation =
        evaluate_members_for_approval(&options, &[BOB_MEMBER_ID.to_string()], ALICE_MEMBER_ID)
            .unwrap();

    assert!(!evaluation.warnings.is_empty());
    assert!(evaluation
        .warnings
        .iter()
        .any(|warning| warning.contains("Insecure permissions")));
}

#[test]
fn test_evaluate_members_for_approval_rejects_incoming_member() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));

    let result =
        evaluate_members_for_approval(&options, &[BOB_MEMBER_ID.to_string()], ALICE_MEMBER_ID);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not found in active/"));
}

#[test]
fn test_evaluate_members_for_approval_excludes_self_from_default_targets() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));

    let evaluation = evaluate_members_for_approval(&options, &[], ALICE_MEMBER_ID).unwrap();

    assert_eq!(evaluation.results.len(), 1);
    assert_eq!(evaluation.results[0].member_id, BOB_MEMBER_ID);
}
