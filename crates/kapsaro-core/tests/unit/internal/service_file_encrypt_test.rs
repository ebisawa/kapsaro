// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{execute_encrypt_file_command, resolve_encrypt_file_command};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::format::content::FileEncContent;
use crate::service::trust::management::remove_known_key_command;
use crate::service::trust::{evaluate_output_recipient_set_trust, ArtifactRecipientTrustOutcome};
use crate::service_test_utils::{
    build_test_signing_command_options, build_test_trust_command_session_from_options,
    resolve_test_write_session, TestCommandOptions,
};
use crate::test_support::storage::keystore::active::set_active_kid;
use crate::test_support::storage::keystore::storage::list_kids;
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
const CAROL_MEMBER_HANDLE: &str = "carol@example.com";

/// The artifact an encrypt writes wraps every active workspace member.
///
/// The rule is what decides who can read the output, so it is fixed here on the
/// stored document rather than through the recipient count a command prints.
#[test]
fn test_encrypt_wraps_every_active_workspace_member() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[
        ALICE_MEMBER_HANDLE,
        BOB_MEMBER_HANDLE,
        CAROL_MEMBER_HANDLE,
    ]);
    activate_member_key(temp_dir.path(), ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let session = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(
        &session.directories,
        &session.trust,
        session.options,
        b"secret".to_vec(),
    )
    .unwrap();

    let encrypted = execute_encrypt_file_command(&command).unwrap();

    let document = FileEncContent::new_unchecked(encrypted).parse().unwrap();
    let mut wrapped = document
        .protected
        .wrap
        .iter()
        .map(|item| (item.recipient_handle.clone(), item.kid.clone()))
        .collect::<Vec<_>>();
    wrapped.sort();
    let keystore_root = temp_dir.path().join("keys");
    let mut expected = [ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE]
        .into_iter()
        .map(|handle| {
            (
                handle.to_string(),
                list_kids(&keystore_root, handle).unwrap().remove(0),
            )
        })
        .collect::<Vec<_>>();
    expected.sort();

    assert_eq!(wrapped, expected);
}

#[test]
fn test_encrypt_output_member_set_auto_accepts_self_only_non_interactive() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    activate_member_key(temp_dir.path(), ALICE_MEMBER_HANDLE);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let session = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(
        &session.directories,
        &session.trust,
        session.options,
        b"secret".to_vec(),
    )
    .unwrap();
    let encrypted = execute_encrypt_file_command(&command).unwrap();
    let document = FileEncContent::new_unchecked(encrypted).parse().unwrap();
    let recipient_set =
        ArtifactRecipientSet::from_wrap_items(document.protected.sid, &document.protected.wrap)
            .unwrap();

    let evaluator = crate::service::trust::snapshot::load_trust_policy_evaluator(
        &session.trust,
        command.trust_context.active_members_by_kid.clone(),
    )
    .unwrap();
    let outcome = evaluate_output_recipient_set_trust(
        &evaluator,
        session.trust.key_ctx(),
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

    let session = resolve_test_write_session(&options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(
        &session.directories,
        &session.trust,
        session.options,
        b"secret".to_vec(),
    )
    .unwrap();

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
    options: TestCommandOptions,
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

    let session = resolve_test_write_session(&fixture.options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(
        &session.directories,
        &session.trust,
        session.options,
        b"secret".to_vec(),
    )
    .unwrap();

    command.ensure_current_after_confirmation().unwrap();
    assert!(execute_encrypt_file_command(&command).is_ok());
}

#[test]
fn test_encrypt_rejects_active_member_change_after_confirmation() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let fixture = setup_approved_two_member_workspace();

    let session = resolve_test_write_session(&fixture.options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(
        &session.directories,
        &session.trust,
        session.options,
        b"secret".to_vec(),
    )
    .unwrap();
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

    let session = resolve_test_write_session(&fixture.options, ALICE_MEMBER_HANDLE);
    let command = resolve_encrypt_file_command(
        &session.directories,
        &session.trust,
        session.options,
        b"secret".to_vec(),
    )
    .unwrap();
    let bob_kid = list_kids(&fixture.temp_dir.path().join("keys"), BOB_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    let trust =
        build_test_trust_command_session_from_options(&fixture.options, ALICE_MEMBER_HANDLE);
    remove_known_key_command(&trust, &bob_kid).unwrap();

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
