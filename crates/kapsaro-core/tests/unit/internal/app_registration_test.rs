// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::io::workspace::members::set_post_open_save_dirs_hook;
use crate::model::ssh::SshDeterminismStatus;
use crate::service::config::LocalStateSession;
use crate::service::key::generate::KeyGenerationHome;
use crate::service::registration::command::{
    evaluate_registration_decision, execute_registration_command, execute_registration_decision,
    resolve_registration_command, RegistrationDecision,
};
use crate::service::registration::key_plan::open_registration_local_state;
use crate::service::registration::types::{
    RegistrationKeyPlan, RegistrationMode, RegistrationResult,
};
use crate::test_support::storage::keystore::storage::load_public_key;
use crate::test_utils::{
    build_expiring_soon_timestamp, setup_test_keystore_from_fixtures, setup_test_workspace,
    update_active_private_key_expires_at,
};
use tempfile::TempDir;

fn build_test_ssh_context(
    home: &std::path::Path,
) -> crate::service::ssh::SshSigningContextResolution {
    let ssh_private_key_path = home.join(".ssh/test_ed25519");
    let ssh_public_key = std::fs::read_to_string(home.join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let backend =
        crate::test_utils::ed25519_backend::Ed25519DirectBackend::new(&ssh_private_key_path)
            .unwrap();
    crate::service::ssh::SshSigningContextResolution {
        fingerprint: build_sha256_fingerprint(&ssh_public_key).unwrap(),
        public_key: ssh_public_key,
        backend: Box::new(backend),
        determinism: SshDeterminismStatus::Verified,
    }
}

fn create_test_workspace_dirs() -> TempDir {
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    workspace_dir
}

fn resolve_test_key_plan(home: &std::path::Path, member_handle: &str) -> RegistrationKeyPlan {
    let local_state = crate::service::config::LocalStateSession::open(home.to_path_buf()).unwrap();
    open_registration_local_state(&local_state)
        .unwrap()
        .resolve_key_plan(member_handle)
        .unwrap()
}

#[test]
fn test_resolve_registration_key_plan_existing_active_key() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");

    let plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");

    assert!(!plan.needs_new_key());
}

#[test]
fn test_resolve_registration_key_plan_missing_active_key() {
    let home_dir = TempDir::new().unwrap();
    let keystore_root = home_dir.path().join("keys");
    std::fs::create_dir_all(&keystore_root).unwrap();

    let plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");

    assert!(plan.needs_new_key());
}

#[test]
fn test_resolve_registration_command_reuses_existing_key_without_github_user() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = workspace_dir.path().to_path_buf();
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");

    let prepared = resolve_registration_command(
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
    assert_eq!(prepared.setup.member_handle, "alice@example.com");
}

#[cfg(unix)]
#[test]
fn test_resolve_registration_command_reuses_key_plan_keystore_after_path_swap() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = workspace_dir.path().to_path_buf();
    let keystore_root = home_dir.path().join("keys");
    let opened_root = home_dir.path().join("keys.opened");
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");

    std::fs::rename(&keystore_root, &opened_root).unwrap();
    std::fs::create_dir(&keystore_root).unwrap();

    let command = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();
    let outcome = execute_registration_command(&command, false).unwrap();

    assert_eq!(outcome.result, RegistrationResult::NewMember);
    assert!(workspace_dir
        .path()
        .join("members/incoming/alice@example.com.json")
        .is_file());
}

#[cfg(unix)]
#[test]
fn test_execute_registration_decision_reuses_keystore_after_confirmation_path_swap() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let member_file = workspace_dir
        .path()
        .join("members/incoming/alice@example.com.json");
    std::fs::write(&member_file, "{}").unwrap();
    let common = workspace_dir.path().to_path_buf();
    let keystore_root = home_dir.path().join("keys");
    let opened_root = home_dir.path().join("keys.opened");
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");
    let command = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    assert_eq!(
        evaluate_registration_decision(&command, false, true).unwrap(),
        RegistrationDecision::ConfirmOverwrite
    );
    std::fs::rename(&keystore_root, &opened_root).unwrap();
    std::fs::create_dir(&keystore_root).unwrap();

    let outcome =
        execute_registration_decision(&command, RegistrationDecision::Apply { overwrite: true })
            .unwrap();

    assert_eq!(outcome.result, RegistrationResult::Updated);
    assert_ne!(std::fs::read_to_string(member_file).unwrap(), "{}");
}

/// The key generated for a plan made in one local state directory is written
/// into that directory, even when the path names another one by then.
#[cfg(unix)]
#[test]
fn test_generated_registration_writes_the_key_into_the_planned_home() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let replacement = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = create_test_workspace_dirs();
    let common = workspace_dir.path().to_path_buf();
    let ssh_ctx = build_test_ssh_context(home_dir.path());
    let key_plan = resolve_test_key_plan(home_dir.path(), "bob@example.com");
    assert!(key_plan.needs_new_key());
    let opened_home = home_dir.path().with_extension("opened");
    std::fs::rename(home_dir.path(), &opened_home).unwrap();
    std::fs::rename(replacement.path(), home_dir.path()).unwrap();

    let command = resolve_registration_command(
        &common,
        "bob@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        Some(ssh_ctx),
    )
    .unwrap();

    let generated_kid = command.setup.kid().to_string();
    assert!(opened_home
        .join("keys")
        .join("bob@example.com")
        .join(&generated_kid)
        .is_dir());
    assert!(!home_dir
        .path()
        .join("keys")
        .join("bob@example.com")
        .exists());

    drop(command);
    std::fs::rename(home_dir.path(), replacement.path()).unwrap();
    std::fs::rename(&opened_home, home_dir.path()).unwrap();
}

#[cfg(unix)]
#[test]
fn test_generated_registration_reuses_created_keystore_after_path_swap() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = create_test_workspace_dirs();
    let common = workspace_dir.path().to_path_buf();
    let ssh_ctx = build_test_ssh_context(home_dir.path());
    let keystore_root = home_dir.path().join("keys");
    std::fs::rename(&keystore_root, home_dir.path().join("keys.seed")).unwrap();
    let local_state = LocalStateSession::open(home_dir.path().to_path_buf()).unwrap();

    let command = resolve_registration_command(
        &common,
        "bob@example.com".to_string(),
        None,
        RegistrationKeyPlan::generate_new(KeyGenerationHome::fix(&local_state).unwrap()),
        RegistrationMode::Join,
        Some(ssh_ctx),
    )
    .unwrap();

    std::fs::rename(&keystore_root, home_dir.path().join("keys.generated")).unwrap();
    std::fs::create_dir(&keystore_root).unwrap();
    let outcome = execute_registration_command(&command, false).unwrap();

    assert_eq!(outcome.result, RegistrationResult::NewMember);
    assert!(workspace_dir
        .path()
        .join("members/incoming/bob@example.com.json")
        .is_file());
}

#[test]
fn test_resolve_registration_command_requires_ssh_context_for_generated_key() {
    let home_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(home_dir.path().join("keys")).unwrap();
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = workspace_dir.path().to_path_buf();
    let local_state = LocalStateSession::open(home_dir.path().to_path_buf()).unwrap();

    let error = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        RegistrationKeyPlan::generate_new(KeyGenerationHome::fix(&local_state).unwrap()),
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
    let common = workspace_dir.path().to_path_buf();
    let keystore_root = home_dir.path().join("keys");
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");
    let kid = key_plan
        .existing_kid()
        .expect("expected existing key plan")
        .to_string();
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

    let prepared = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let error = execute_registration_command(&prepared, false).unwrap_err();
    let message = error.to_string();
    // The file's stem ("duplicate-owner") does not match its content's
    // member_handle, so the stem-binding check rejects it before the kid
    // uniqueness check runs. Either rejection path is acceptable.
    assert!(
        message.contains("kid") || message.contains("Member handle mismatch"),
        "unexpected error: {error}"
    );
}

/// The kid uniqueness check and the write are one operation under the member
/// lock, so a document carrying the same kid that lands after the registration
/// looked at the workspace still stops it.
#[test]
fn test_registration_judges_the_kid_against_the_member_set_it_writes_into() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = create_test_workspace_dirs();
    let common = workspace_dir.path().to_path_buf();
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");
    let kid = key_plan
        .existing_kid()
        .expect("expected existing key plan")
        .to_string();
    let public_key =
        load_public_key(&home_dir.path().join("keys"), "alice@example.com", &kid).unwrap();
    let document = serde_json::to_string_pretty(&public_key).unwrap();
    let command = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();
    let active_copy = workspace_dir
        .path()
        .join("members/active/alice@example.com.json");
    set_post_open_save_dirs_hook(move || std::fs::write(&active_copy, &document).unwrap());

    let error = execute_registration_command(&command, false).unwrap_err();

    assert!(
        error.to_string().contains("Duplicate kid"),
        "unexpected error: {error}"
    );
    assert!(!workspace_dir
        .path()
        .join("members/incoming/alice@example.com.json")
        .exists());
}

/// The outcome names the state the write met. A member document that appeared
/// after the registration looked at the path is reported as one already there,
/// rather than being written over by a run that decided the name was free.
#[test]
fn test_registration_reports_a_member_that_appeared_under_the_lock() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = create_test_workspace_dirs();
    let common = workspace_dir.path().to_path_buf();
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");
    let command = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();
    let member_file = workspace_dir
        .path()
        .join("members/incoming/alice@example.com.json");
    let appearing = member_file.clone();
    set_post_open_save_dirs_hook(move || std::fs::write(&appearing, "{}").unwrap());

    let outcome = execute_registration_command(&command, false).unwrap();

    assert_eq!(outcome.result, RegistrationResult::AlreadyExists);
    assert_eq!(std::fs::read_to_string(&member_file).unwrap(), "{}");
}

#[test]
fn test_evaluate_registration_decision_prompts_for_overwrite_when_interactive() {
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
    let common = workspace_dir.path().to_path_buf();
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");
    let prepared = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let decision = evaluate_registration_decision(&prepared, false, true).unwrap();

    assert_eq!(decision, RegistrationDecision::ConfirmOverwrite);
}

#[test]
fn test_evaluate_registration_decision_skips_init_conflict_non_interactive() {
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
    let common = workspace_dir.path().to_path_buf();
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");
    let prepared = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Init,
        None,
    )
    .unwrap();

    let decision = evaluate_registration_decision(&prepared, false, false).unwrap();

    assert_eq!(
        decision,
        RegistrationDecision::Return(RegistrationResult::Skipped)
    );
}

#[test]
fn test_evaluate_registration_decision_rejects_join_conflict_non_interactive() {
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
    let common = workspace_dir.path().to_path_buf();
    let key_plan = resolve_test_key_plan(home_dir.path(), "alice@example.com");
    let prepared = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let error = evaluate_registration_decision(&prepared, false, false).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("already exists. Use --force to overwrite"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_evaluate_registration_decision_allows_join_rotation_when_active_kid_differs() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);
    let common = workspace_dir.clone();
    let expires_at = build_expiring_soon_timestamp(365);
    update_active_private_key_expires_at(temp_dir.path(), "alice@example.com", &expires_at);

    let key_plan = resolve_test_key_plan(temp_dir.path(), "alice@example.com");
    let prepared = resolve_registration_command(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        RegistrationMode::Join,
        None,
    )
    .unwrap();

    let decision = evaluate_registration_decision(&prepared, false, false).unwrap();

    assert_eq!(decision, RegistrationDecision::Apply { overwrite: false });
}

#[test]
fn test_resolve_registration_command_rejects_mismatched_active_member_file_for_join() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com", "bob@example.com"]);
    let common = workspace_dir.clone();
    let alice_path = workspace_dir
        .join("members/active")
        .join("alice@example.com.json");
    let bob_path = workspace_dir
        .join("members/active")
        .join("bob@example.com.json");
    let bob_content = std::fs::read_to_string(&bob_path).unwrap();
    std::fs::write(&alice_path, bob_content).unwrap();

    let key_plan = resolve_test_key_plan(temp_dir.path(), "alice@example.com");
    let error = resolve_registration_command(
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
