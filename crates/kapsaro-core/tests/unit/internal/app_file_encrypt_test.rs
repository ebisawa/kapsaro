// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{execute_encrypt_file_command, resolve_encrypt_file_command};
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::management::remove_known_key_command;
use crate::app::trust::{evaluate_output_recipient_set_trust, ArtifactRecipientTrustOutcome};
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_write_execution};
use crate::cli_api::test_support::storage::keystore::active::set_active_kid;
use crate::cli_api::test_support::storage::keystore::storage::list_kids;
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::format::content::FileEncContent;
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
    update_active_private_key_expires_at, EnvGuard,
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

#[test]
fn test_encrypt_output_member_set_auto_accepts_self_only_non_interactive() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    activate_member_key(temp_dir.path(), ALICE_MEMBER_HANDLE);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(&options, &execution, b"secret".to_vec()).unwrap();
    let encrypted = execute_encrypt_file_command(&command).unwrap();
    let document = FileEncContent::new_unchecked(encrypted).parse().unwrap();
    let recipient_set =
        ArtifactRecipientSet::from_wrap_items(document.protected.sid, &document.protected.wrap)
            .unwrap();

    let evaluator = crate::app::trust::snapshot::load_trust_policy_evaluator(
        command.execution,
        command.trust_context.active_members_by_kid.clone(),
    )
    .unwrap();
    let outcome = evaluate_output_recipient_set_trust(
        &evaluator,
        &command.execution.key_ctx,
        &command.trust_context,
        &recipient_set,
    )
    .unwrap();

    assert_eq!(outcome, ArtifactRecipientTrustOutcome::Accepted);
}

#[test]
fn test_encrypt_command_coalesces_local_key_pair_expiry_warning() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_HANDLE)
        .unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(&options, &execution, b"secret".to_vec()).unwrap();

    let expiry_warning_count = command
        .warnings
        .iter()
        .filter(|warning| warning.contains(&expires_at))
        .count();
    assert_eq!(expiry_warning_count, 1, "{:?}", command.warnings);
    assert!(command
        .warnings
        .iter()
        .any(|warning| warning.contains("Local key expires in")));
}

/// A workspace holding two approved members, which is what lets a test move one
/// of them without the plan being refused before the confirmation is reached.
struct ApprovedTwoMemberWorkspace {
    temp_dir: TempDir,
    workspace_dir: PathBuf,
    options: CommonCommandOptions,
}

fn setup_approved_two_member_workspace() -> ApprovedTwoMemberWorkspace {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    activate_member_key(temp_dir.path(), ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    ApprovedTwoMemberWorkspace {
        temp_dir,
        workspace_dir,
        options,
    }
}

fn activate_member_key(home: &Path, member_handle: &str) {
    let keystore_root = home.join("keys");
    let kid = list_kids(&keystore_root, member_handle)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(member_handle, &kid, &keystore_root).unwrap();
}

fn workspace_member_path(workspace_dir: &Path, member_dir: &str, member_handle: &str) -> PathBuf {
    workspace_dir
        .join("members")
        .join(member_dir)
        .join(format!("{member_handle}.json"))
}

#[test]
fn test_encrypt_accepts_unchanged_review_state_after_confirmation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let fixture = setup_approved_two_member_workspace();

    let execution = resolve_test_write_execution(&fixture.options, ALICE_MEMBER_HANDLE);
    let command =
        resolve_encrypt_file_command(&fixture.options, &execution, b"secret".to_vec()).unwrap();

    command.ensure_current_after_confirmation().unwrap();
    assert!(execute_encrypt_file_command(&command).is_ok());
}

#[test]
fn test_encrypt_rejects_active_member_change_after_confirmation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let fixture = setup_approved_two_member_workspace();

    let execution = resolve_test_write_execution(&fixture.options, ALICE_MEMBER_HANDLE);
    let command =
        resolve_encrypt_file_command(&fixture.options, &execution, b"secret".to_vec()).unwrap();
    fs::rename(
        workspace_member_path(&fixture.workspace_dir, "active", BOB_MEMBER_HANDLE),
        workspace_member_path(&fixture.workspace_dir, "incoming", BOB_MEMBER_HANDLE),
    )
    .unwrap();

    let error = command
        .ensure_current_after_confirmation()
        .expect_err("expected active member snapshot mismatch error");

    assert!(
        error
            .to_string()
            .contains("Encrypt active members changed since review"),
        "{error}"
    );
}

#[test]
fn test_encrypt_rejects_trust_store_change_after_confirmation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let fixture = setup_approved_two_member_workspace();

    let execution = resolve_test_write_execution(&fixture.options, ALICE_MEMBER_HANDLE);
    let command =
        resolve_encrypt_file_command(&fixture.options, &execution, b"secret".to_vec()).unwrap();
    let bob_kid = list_kids(&fixture.temp_dir.path().join("keys"), BOB_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    remove_known_key_command(&fixture.options, &execution, &bob_kid).unwrap();

    let error = command
        .ensure_current_after_confirmation()
        .expect_err("expected trust store snapshot mismatch error");

    assert!(
        error
            .to_string()
            .contains("Encrypt trust store changed since review"),
        "{error}"
    );
}
