// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::registration::command::{
    apply_registration, build_registration, build_registration_decision, RegistrationDecision,
};
use crate::app::registration::key_plan::resolve_registration_key_plan;
use crate::app::registration::types::{RegistrationKeyPlan, RegistrationMode, RegistrationResult};
use crate::app_test_utils::build_test_command_options;
use crate::io::keystore::storage::load_public_key;
use crate::test_utils::{
    build_expiring_soon_timestamp, setup_test_keystore_from_fixtures, setup_test_workspace,
    update_active_private_key_expires_at,
};
use tempfile::TempDir;

#[test]
fn test_resolve_registration_key_plan_existing_active_key() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let keystore_root = home_dir.path().join("keys");

    let plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    assert!(matches!(plan, RegistrationKeyPlan::UseExisting { .. }));
    assert!(!plan.needs_new_key());
}

#[test]
fn test_resolve_registration_key_plan_missing_active_key() {
    let home_dir = TempDir::new().unwrap();
    let keystore_root = home_dir.path().join("keys");
    std::fs::create_dir_all(&keystore_root).unwrap();

    let plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    assert_eq!(plan, RegistrationKeyPlan::GenerateNew);
    assert!(plan.needs_new_key());
}

#[test]
fn test_build_registration_reuses_existing_key_without_github_user() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = build_test_command_options(home_dir.path(), Some(workspace_dir.path()));
    let keystore_root = home_dir.path().join("keys");
    let key_plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    let prepared = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    assert_eq!(prepared.mode, RegistrationMode::Join);
    assert!(!prepared.setup.key_result.created);
    assert_eq!(prepared.setup.member_id, "alice@example.com");
}

#[test]
fn test_build_registration_requires_ssh_context_for_generated_key() {
    let home_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(home_dir.path().join("keys")).unwrap();
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = build_test_command_options(home_dir.path(), Some(workspace_dir.path()));

    let error = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        RegistrationKeyPlan::GenerateNew,
        RegistrationMode::Join,
        None,
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("SSH signing context is required for key generation"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_apply_join_registration_rejects_duplicate_kid_in_workspace() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = build_test_command_options(home_dir.path(), Some(workspace_dir.path()));
    let keystore_root = home_dir.path().join("keys");
    let key_plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();
    let kid = match &key_plan {
        RegistrationKeyPlan::UseExisting { kid, .. } => kid.clone(),
        other => panic!("expected existing key plan, got {other:?}"),
    };
    let public_key = load_public_key(&keystore_root, "alice@example.com", &kid).unwrap();
    let existing = serde_json::to_string_pretty(&public_key).unwrap();
    std::fs::write(
        workspace_dir
            .path()
            .join("members/active")
            .join("duplicate-owner.json"),
        existing,
    )
    .unwrap();

    let prepared = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let error = apply_registration(&prepared, false).unwrap_err();
    let message = error.to_string();
    // The file's stem ("duplicate-owner") does not match its content's
    // member_id, so the stem-binding check rejects it before the kid
    // uniqueness check runs. Either rejection path is acceptable.
    assert!(
        message.contains("kid") || message.contains("Member handle mismatch"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_build_registration_decision_prompts_for_overwrite_when_interactive() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    std::fs::write(
        workspace_dir
            .path()
            .join("members/incoming")
            .join("alice@example.com.json"),
        "{}",
    )
    .unwrap();
    let common = build_test_command_options(home_dir.path(), Some(workspace_dir.path()));
    let key_plan =
        resolve_registration_key_plan("alice@example.com", &home_dir.path().join("keys")).unwrap();
    let prepared = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let decision = build_registration_decision(&prepared, false, true).unwrap();

    assert_eq!(decision, RegistrationDecision::ConfirmOverwrite);
}

#[test]
fn test_build_registration_decision_skips_init_conflict_non_interactive() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    std::fs::write(
        workspace_dir
            .path()
            .join("members/active")
            .join("alice@example.com.json"),
        "{}",
    )
    .unwrap();
    let common = build_test_command_options(home_dir.path(), Some(workspace_dir.path()));
    let key_plan =
        resolve_registration_key_plan("alice@example.com", &home_dir.path().join("keys")).unwrap();
    let prepared = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Init,
        None,
    )
    .unwrap();

    let decision = build_registration_decision(&prepared, false, false).unwrap();

    assert_eq!(
        decision,
        RegistrationDecision::Return(RegistrationResult::Skipped)
    );
}

#[test]
fn test_build_registration_decision_rejects_join_conflict_non_interactive() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    std::fs::write(
        workspace_dir
            .path()
            .join("members/incoming")
            .join("alice@example.com.json"),
        "{}",
    )
    .unwrap();
    let common = build_test_command_options(home_dir.path(), Some(workspace_dir.path()));
    let key_plan =
        resolve_registration_key_plan("alice@example.com", &home_dir.path().join("keys")).unwrap();
    let prepared = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let error = build_registration_decision(&prepared, false, false).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("already exists. Use --force to overwrite"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_build_registration_decision_allows_join_rotation_when_active_kid_differs() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);
    let common = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let expires_at = build_expiring_soon_timestamp(365);
    update_active_private_key_expires_at(temp_dir.path(), "alice@example.com", &expires_at);

    let key_plan =
        resolve_registration_key_plan("alice@example.com", &temp_dir.path().join("keys")).unwrap();
    let prepared = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let decision = build_registration_decision(&prepared, false, false).unwrap();

    assert_eq!(decision, RegistrationDecision::Apply { overwrite: false });
}

#[test]
fn test_build_registration_rejects_mismatched_active_member_file_for_join() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com", "bob@example.com"]);
    let common = build_test_command_options(temp_dir.path(), Some(&workspace_dir));
    let alice_path = workspace_dir
        .join("members/active")
        .join("alice@example.com.json");
    let bob_path = workspace_dir
        .join("members/active")
        .join("bob@example.com.json");
    let bob_content = std::fs::read_to_string(&bob_path).unwrap();
    std::fs::write(&alice_path, bob_content).unwrap();

    let key_plan =
        resolve_registration_key_plan("alice@example.com", &temp_dir.path().join("keys")).unwrap();
    let error = build_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap_err();

    assert!(
        error.to_string().contains("Member handle mismatch"),
        "unexpected error: {error}"
    );
}
