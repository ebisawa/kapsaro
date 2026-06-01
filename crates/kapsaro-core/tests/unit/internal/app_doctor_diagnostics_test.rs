// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::app::doctor::ci::check_ci_readiness;
use crate::app::doctor::types::{DoctorCheck, DoctorStatus};
use crate::app::doctor::{execute_doctor_command, DoctorRequest};
use crate::feature::context::crypto::SigningContext;
use crate::feature::kv::encrypt::encrypt_kv_document;
use crate::feature::trust::signature::sign_trust_store;
use crate::format::token::TokenCodec;
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::paths::get_private_key_file_path_from_root;
use crate::io::keystore::storage::{list_kids, load_public_key};
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::save_trust_store;
use crate::model::trust_store::TrustStoreProtected;
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    setup_member_key_context, setup_test_workspace_from_fixtures, EnvGuard, ALICE_MEMBER_HANDLE,
    BOB_MEMBER_HANDLE,
};
use tempfile::TempDir;

fn doctor_request(home: &TempDir, workspace: &Path) -> DoctorRequest {
    DoctorRequest {
        workspace: Some(workspace.to_path_buf()),
        home: Some(home.path().to_path_buf()),
        member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
        debug: false,
        verbose: false,
    }
}

fn run_workspace_doctor(home: &TempDir, workspace: &Path) -> Vec<DoctorCheck> {
    execute_doctor_command(doctor_request(home, workspace))
        .unwrap()
        .checks()
        .to_vec()
}

fn has_check(checks: &[DoctorCheck], id: &str, status: DoctorStatus) -> bool {
    checks
        .iter()
        .any(|check| check.id == id && check.status == status)
}

fn create_workspace_dirs(workspace: &Path) {
    fs::create_dir_all(workspace.join("members/active")).unwrap();
    fs::create_dir_all(workspace.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace.join("secrets")).unwrap();
}

fn save_empty_trust_store(home: &TempDir) {
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-05-10T00:00:00Z".to_string(),
        updated_at: "2026-05-10T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE);
    save_trust_store(&path, &document).unwrap();
}

fn encrypted_kv_for_alice_only(home: &TempDir) -> String {
    encrypted_kv_for_recipients(home, ALICE_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE])
}

fn encrypted_kv_for_recipients(
    home: &TempDir,
    signer_handle: &str,
    recipient_handles: &[&str],
) -> String {
    let keystore_root = home.path().join("keys");
    let kid = list_kids(&keystore_root, signer_handle)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let signer_pub = load_public_key(&keystore_root, signer_handle, &kid).unwrap();
    let key_ctx = setup_member_key_context(home, signer_handle, Some(&kid));
    let recipients = recipient_handles
        .iter()
        .map(|handle| {
            let kid = list_kids(&keystore_root, handle)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            load_public_key(&keystore_root, handle, &kid).unwrap()
        })
        .collect::<Vec<_>>();
    let verified_members = build_verified_recipient_keys(&recipients);
    let mut values = HashMap::new();
    values.insert("API_TOKEN".to_string(), "secret".to_string());
    let signing = SigningContext {
        signing_key: key_ctx.signing_key(),
        signer_kid: &kid,
        signer_pub,
        debug: false,
    };
    encrypt_kv_document(&values, &verified_members, &signing, TokenCodec::JsonJcs).unwrap()
}

fn encrypted_kv_for_mislabeled_bob_recipient(home: &TempDir) -> String {
    let keystore_root = home.path().join("keys");
    let signer_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let signer_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &signer_kid).unwrap();
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_HANDLE, Some(&signer_kid));
    let bob_kid = list_kids(&keystore_root, BOB_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let mut mislabeled_bob = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, &bob_kid).unwrap();
    mislabeled_bob.protected.subject_handle = ALICE_MEMBER_HANDLE.to_string();
    let verified_members = build_verified_recipient_keys(&[mislabeled_bob]);
    let mut values = HashMap::new();
    values.insert("API_TOKEN".to_string(), "secret".to_string());
    let signing = SigningContext {
        signing_key: key_ctx.signing_key(),
        signer_kid: &signer_kid,
        signer_pub,
        debug: false,
    };
    encrypt_kv_document(&values, &verified_members, &signing, TokenCodec::JsonJcs).unwrap()
}

#[test]
fn test_doctor_ci_invalid_env_key_reports_fail_and_strict_warning() {
    let _guard = EnvGuard::new(&[
        "KAPSARO_PRIVATE_KEY",
        "KAPSARO_KEY_PASSWORD",
        "KAPSARO_STRICT_KEY_CHECKING",
    ]);
    std::env::set_var("KAPSARO_PRIVATE_KEY", "not-base64url");
    std::env::set_var("KAPSARO_KEY_PASSWORD", "password");
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");
    let home = TempDir::new().unwrap();
    let options = DoctorRequest {
        workspace: None,
        home: Some(home.path().to_path_buf()),
        member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
        debug: false,
        verbose: false,
    }
    .common_options();
    let checks = check_ci_readiness(&options);

    assert!(
        has_check(&checks, "ci.env_key.present", DoctorStatus::Ok),
        "{checks:?}"
    );
    assert!(has_check(
        &checks,
        "ci.strict_key_checking",
        DoctorStatus::Warn
    ));
    assert!(has_check(&checks, "ci.env_key.load", DoctorStatus::Fail));
}

#[test]
fn test_doctor_ci_env_key_absent_reports_skip() {
    let _guard = EnvGuard::new(&["KAPSARO_PRIVATE_KEY", "KAPSARO_KEY_PASSWORD"]);
    std::env::remove_var("KAPSARO_PRIVATE_KEY");
    std::env::remove_var("KAPSARO_KEY_PASSWORD");
    let home = TempDir::new().unwrap();
    let options = DoctorRequest {
        workspace: None,
        home: Some(home.path().to_path_buf()),
        member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
        debug: false,
        verbose: false,
    }
    .common_options();
    let checks = check_ci_readiness(&options);

    assert!(has_check(&checks, "ci.env_key.present", DoctorStatus::Skip));
}

#[test]
fn test_doctor_reports_missing_keystore_root_as_warning() {
    let home = TempDir::new().unwrap();
    let workspace = home.path().join("workspace");
    create_workspace_dirs(&workspace);

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "keystore.root", DoctorStatus::Warn));
}

#[test]
fn test_doctor_reports_missing_active_private_key_as_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = home.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
    let private_path =
        get_private_key_file_path_from_root(&keystore_root, ALICE_MEMBER_HANDLE, &kid);
    fs::remove_file(private_path).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "keystore.private_key",
        DoctorStatus::Fail
    ));
}

#[test]
fn test_doctor_reports_invalid_trust_store_signature_as_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let trust_path = get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE);
    fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    fs::write(&trust_path, "{invalid-json").unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "trust_store.signature",
        DoctorStatus::Fail
    ));
}

#[test]
fn test_doctor_warns_when_active_member_is_not_approved() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    save_empty_trust_store(&home);

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "trust_store.active_approval",
        DoctorStatus::Warn
    ));
}

#[test]
fn test_doctor_reports_incoming_member_and_duplicate_kid() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let active_file = workspace
        .join("members/active")
        .join(format!("{}.json", ALICE_MEMBER_HANDLE));
    let incoming_file = workspace.join("members/incoming/duplicate.json");
    fs::copy(active_file, incoming_file).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "members.incoming.pending",
        DoctorStatus::Warn
    ));
    assert!(has_check(&checks, "members.kid_unique", DoctorStatus::Fail));
}

#[test]
fn test_doctor_reports_invalid_artifact_read_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    fs::write(
        workspace.join("secrets/bad.kvenc"),
        "not an encrypted artifact",
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "artifacts.read", DoctorStatus::Fail));
}

#[test]
fn test_doctor_warns_when_artifact_recipients_differ_from_active_members() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let content = encrypted_kv_for_alice_only(&home);
    fs::write(workspace.join("secrets/default.kvenc"), content).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "artifact.signature", DoctorStatus::Ok));
    assert!(has_check(
        &checks,
        "artifact.signer_active",
        DoctorStatus::Ok
    ));
    assert!(has_check(
        &checks,
        "artifact.recipients_active",
        DoctorStatus::Warn
    ));
}

#[test]
fn test_doctor_reports_tampered_artifact_signature_failure() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let content = encrypted_kv_for_alice_only(&home).replacen("API_TOKEN", "API_TOKFN", 1);
    fs::write(workspace.join("secrets/default.kvenc"), content).unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(&checks, "artifact.signature", DoctorStatus::Fail));
    assert!(!has_check(
        &checks,
        "artifact.signer_active",
        DoctorStatus::Ok
    ));
}

#[test]
fn test_doctor_reports_artifact_signer_not_active() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    fs::write(
        workspace.join("secrets/default.kvenc"),
        encrypted_kv_for_alice_only(&home),
    )
    .unwrap();
    fs::remove_file(
        workspace
            .join("members/active")
            .join(format!("{}.json", ALICE_MEMBER_HANDLE)),
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "artifact.signer_active",
        DoctorStatus::Fail
    ));
}

#[test]
fn test_doctor_reports_artifact_recipient_handle_conflict() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    fs::write(
        workspace.join("secrets/default.kvenc"),
        encrypted_kv_for_mislabeled_bob_recipient(&home),
    )
    .unwrap();

    let checks = run_workspace_doctor(&home, &workspace);

    assert!(has_check(
        &checks,
        "artifact.recipient_handle",
        DoctorStatus::Fail
    ));
}

#[test]
fn test_doctor_without_member_handle_reports_owner_warnings_when_ambiguous() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let request = DoctorRequest {
        workspace: Some(workspace),
        home: Some(home.path().to_path_buf()),
        member_handle: None,
        debug: false,
        verbose: false,
    };

    let checks = execute_doctor_command(request).unwrap().checks().to_vec();

    assert!(has_check(&checks, "keystore.member", DoctorStatus::Warn));
    assert!(has_check(
        &checks,
        "trust_store.present",
        DoctorStatus::Warn
    ));
}
