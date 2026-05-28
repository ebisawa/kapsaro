// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    evaluate_encrypt_output_recipient_set, execute_encrypt_file_command,
    resolve_encrypt_file_command,
};
use crate::app::trust::ArtifactRecipientTrustOutcome;
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_ssh_context};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::format::content::FileEncContent;
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::storage::list_kids;
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace,
    setup_test_workspace_from_fixtures, update_active_private_key_expires_at, EnvGuard,
};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";

#[test]
fn test_encrypt_output_member_set_auto_accepts_self_only_non_interactive() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let command = resolve_encrypt_file_command(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        b"secret".to_vec(),
        Some(resolve_test_ssh_context(&options, ALICE_MEMBER_HANDLE)),
    )
    .unwrap();
    let encrypted = execute_encrypt_file_command(&command, false).unwrap();
    let document = FileEncContent::new_unchecked(encrypted).parse().unwrap();
    let recipient_set =
        ArtifactRecipientSet::from_wrap_items(document.protected.sid, &document.protected.wrap)
            .unwrap();

    let outcome = evaluate_encrypt_output_recipient_set(&command, &recipient_set).unwrap();

    assert_eq!(outcome, ArtifactRecipientTrustOutcome::Accepted);
}

#[test]
fn test_encrypt_command_coalesces_local_key_pair_expiry_warning() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_HANDLE)
        .unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let command = resolve_encrypt_file_command(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        b"secret".to_vec(),
        Some(resolve_test_ssh_context(&options, ALICE_MEMBER_HANDLE)),
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
