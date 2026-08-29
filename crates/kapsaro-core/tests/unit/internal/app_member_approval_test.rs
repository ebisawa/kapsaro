// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::app::member::approval::{
    evaluate_members_for_approval, save_member_approvals, MemberApprovalResult,
};
use crate::app_test_utils::{
    build_test_command_options, build_test_execution_context, load_test_trust_store,
};
#[cfg(feature = "online")]
use crate::test_utils::member_handle;
use crate::test_utils::setup_test_workspace_from_fixtures;
#[cfg(feature = "online")]
use crate::{
    io::trust::paths::get_trust_store_file_path, support::warning::LocalStateWarningGuard,
};
use crate::{
    io::verify_online::VerifiedGithubIdentity, io::workspace::members::load_active_member_files,
    model::public_key::PublicKey,
};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

fn find_kid(active_members: &[PublicKey], member_handle: &str) -> String {
    active_members
        .iter()
        .find(|pk| pk.protected.subject_handle == member_handle)
        .map(|pk| pk.protected.kid.clone())
        .unwrap()
}

fn find_member(active_members: &[PublicKey], member_handle: &str) -> PublicKey {
    active_members
        .iter()
        .find(|pk| pk.protected.subject_handle == member_handle)
        .cloned()
        .unwrap()
}

/// One manually reviewed approval for Bob, as the review step would leave it.
fn build_manual_approval(kid: &str, verified: bool, attestor_pub: &str) -> MemberApprovalResult {
    MemberApprovalResult {
        member_handle: BOB_MEMBER_HANDLE.to_string(),
        kid: kid.to_string(),
        verified,
        approved: true,
        review_required: true,
        already_known: false,
        message: "manual review".to_string(),
        fingerprint: None,
        github_id: None,
        github_login: None,
        github_binding_configured: false,
        attestor_pub: Some(attestor_pub.to_string()),
        verified_github: None,
    }
}

#[test]
fn test_save_member_approvals_persists_only_manually_approved_candidates() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob_kid = find_kid(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    save_member_approvals(
        &options,
        &[build_manual_approval(
            &bob_kid,
            false,
            &find_member(&active_members, BOB_MEMBER_HANDLE)
                .protected
                .attestation
                .pub_,
        )],
        &execution,
    )
    .unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    assert!(loaded
        .protected
        .known_keys
        .iter()
        .any(|entry| entry.subject_handle == BOB_MEMBER_HANDLE && entry.kid == bob_kid));
}

#[test]
fn test_save_member_approvals_rejects_expired_signing_key() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob_kid = find_kid(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    crate::test_utils::update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let result = save_member_approvals(
        &options,
        &[build_manual_approval(
            &bob_kid,
            false,
            &find_member(&active_members, BOB_MEMBER_HANDLE)
                .protected
                .attestation
                .pub_,
        )],
        &execution,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    assert!(load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .is_none());
}

#[test]
fn test_member_verify_approve_rejects_an_expired_target_key() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let mut active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = active_members
        .iter_mut()
        .find(|pk| pk.protected.subject_handle == BOB_MEMBER_HANDLE)
        .unwrap();
    bob.protected.expires_at = "2020-01-01T00:00:00Z".to_string();
    let error = super::evaluate_candidate_with_snapshot(
        &crate::io::verify_online::VerificationResult::not_configured(
            BOB_MEMBER_HANDLE,
            "manual review",
            None,
            false,
        ),
        &active_members,
        &[],
    )
    .unwrap_err();

    assert_eq!(error.rule(), Some("E_KEY_EXPIRED"));
    assert!(error.to_string().contains("expired"));
}

#[test]
fn test_save_member_approvals_uses_evaluated_snapshot_without_rereading_workspace() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let original_attestor_pub = bob.protected.attestation.pub_.clone();
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));
    let bob_file = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let mut tampered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bob_file).unwrap()).unwrap();
    tampered["protected"]["attestation"]["pub"] =
        serde_json::Value::String("ssh-ed25519 AAAA changed".to_string());
    fs::write(&bob_file, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

    save_member_approvals(
        &options,
        &[build_manual_approval(
            &bob.protected.kid,
            true,
            &original_attestor_pub,
        )],
        &execution,
    )
    .unwrap();

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let saved = loaded
        .protected
        .known_keys
        .iter()
        .find(|entry| entry.subject_handle == BOB_MEMBER_HANDLE)
        .unwrap();
    assert_eq!(
        saved.evidence.as_ref().unwrap().ssh_attestor_pub.as_deref(),
        Some(original_attestor_pub.as_str())
    );
}

#[test]
fn test_save_member_approvals_persists_verified_github_login_from_review() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    save_member_approvals(
        &options,
        &[MemberApprovalResult {
            member_handle: BOB_MEMBER_HANDLE.to_string(),
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
            attestor_pub: Some(bob.protected.attestation.pub_.clone()),
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

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    let saved = loaded
        .protected
        .known_keys
        .iter()
        .find(|entry| entry.subject_handle == BOB_MEMBER_HANDLE)
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
#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_warns_about_insecure_trust_store() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    save_member_approvals(
        &options,
        &[build_manual_approval(
            &bob.protected.kid,
            true,
            &bob.protected.attestation.pub_,
        )],
        &execution,
    )
    .unwrap();

    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let warning_guard = LocalStateWarningGuard::new();
    evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]).unwrap();
    let warnings = warning_guard.take_reasons();

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0644"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("chmod 0600"), "{warnings:?}");
}

/// The evaluation reads the trust store of the home the command resolved,
/// even when another directory takes that path before the review starts.
#[cfg(unix)]
#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_reads_trust_store_of_fixed_home() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let bob = find_member(&active_members, BOB_MEMBER_HANDLE);
    let options = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));
    save_member_approvals(
        &options,
        &[build_manual_approval(
            &bob.protected.kid,
            true,
            &bob.protected.attestation.pub_,
        )],
        &execution,
    )
    .unwrap();

    // A second fixture home holds the same workspace and keystore, but no
    // trust store: reading it would report Bob as an unreviewed candidate.
    let (replacement, _) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let opened_home = temp_dir.path().with_extension("opened");
    fs::rename(temp_dir.path(), &opened_home).unwrap();
    fs::rename(replacement.path(), temp_dir.path()).unwrap();

    let evaluation =
        evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]).unwrap();

    assert_eq!(evaluation.results.len(), 1);
    assert!(
        evaluation.results[0].already_known,
        "{:?}",
        evaluation.results[0]
    );

    drop(execution);
    fs::rename(temp_dir.path(), replacement.path()).unwrap();
    fs::rename(&opened_home, temp_dir.path()).unwrap();
}

/// The evaluation reads the member set of the workspace the command resolved,
/// even when another tree takes that path before the review starts.
#[cfg(unix)]
#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_reads_members_of_fixed_workspace() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    // A second workspace holds Alice alone, so a read addressed by path would
    // report Bob as missing from active/.
    let (_replacement, replacement_workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let opened_workspace = workspace_dir.with_extension("opened");
    fs::rename(&workspace_dir, &opened_workspace).unwrap();
    fs::rename(&replacement_workspace, &workspace_dir).unwrap();

    let evaluation =
        evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]).unwrap();

    assert_eq!(evaluation.results.len(), 1);
    assert_eq!(evaluation.results[0].member_handle, BOB_MEMBER_HANDLE);
}

#[test]
fn test_evaluate_members_for_approval_rejects_incoming_member() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let result = evaluate_members_for_approval(&execution, &[BOB_MEMBER_HANDLE.to_string()]);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not found in active/"));
}

#[cfg(feature = "online")]
#[test]
fn test_evaluate_members_for_approval_excludes_self_from_default_targets() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let execution =
        build_test_execution_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&workspace_dir));

    let evaluation = evaluate_members_for_approval(&execution, &[]).unwrap();

    assert_eq!(evaluation.results.len(), 1);
    assert_eq!(evaluation.results[0].member_handle, BOB_MEMBER_HANDLE);
}
