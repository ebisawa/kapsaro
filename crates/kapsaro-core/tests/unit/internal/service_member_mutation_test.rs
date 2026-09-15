// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::{evaluate_member_removal, remove_member};
use crate::feature::context::crypto::SigningContext;
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::kv::encrypt::encrypt_kv_map_with_wrap_mutation;
use crate::format::token::TokenCodec;
use crate::io::workspace::members::load_active_member_files;
use crate::service::workspace::{WorkspaceAccess, WorkspaceKind};
use crate::support::fs::test_umask::{isolated_umask_test, with_umask};
use crate::test_support::storage::keystore::storage::{list_kids, load_public_key};
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{setup_member_key_context, setup_test_workspace_from_fixtures};
use serde_json::Value;
use tempfile::TempDir;

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

isolated_umask_test! {
    fn test_member_add_global_directory_permissions() {
        for mask in [0o022, 0o777] {
            for existing_members in [false, true] {
                assert_member_add_permissions(WorkspaceKind::Global, mask, existing_members);
            }
        }
    }
}

isolated_umask_test! {
    fn test_member_add_regular_directory_permissions() {
        assert_member_add_permissions(WorkspaceKind::Regular, 0o022, false);
    }
}

fn assert_member_add_permissions(kind: WorkspaceKind, mask: libc::mode_t, existing: bool) {
    use crate::service::diagnostics::{take_local_state_warnings, DiagnosticCode};
    use crate::service::file::FileInputTarget;

    let (_home, source) = setup_test_workspace_from_fixtures(&[BOB_MEMBER_HANDLE]);
    let key = source.join(format!("members/active/{BOB_MEMBER_HANDLE}.json"));
    let content = fs::read(&key).unwrap();
    let input = FileInputTarget::open(&key, None).unwrap();
    let destination = TempDir::new().unwrap();
    fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let members = destination.path().join("members");
    if existing {
        fs::create_dir(&members).unwrap();
        fs::set_permissions(&members, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let access = WorkspaceAccess::open(destination.path(), kind).unwrap();
    take_local_state_warnings();
    with_umask(mask, || {
        assert_eq!(
            super::add_member(&access, &input, false).unwrap(),
            BOB_MEMBER_HANDLE
        );
    });
    assert_member_storage_permissions(&members, kind, existing);
    let saved = members.join(format!("incoming/{BOB_MEMBER_HANDLE}.json"));
    assert_eq!(fs::read(&saved).unwrap(), content);
    let warnings = take_local_state_warnings();
    if existing {
        assert!(warnings.diagnostics().iter().any(|finding| {
            finding.code() == DiagnosticCode::GlobalWorkspacePermissions
                && finding.path() == members
        }));
    }
}

fn assert_member_storage_permissions(members: &Path, kind: WorkspaceKind, existing: bool) {
    let mode = if kind == WorkspaceKind::Global {
        0o700
    } else {
        0o755
    };
    for (path, expected) in [
        (members.to_path_buf(), if existing { 0o755 } else { mode }),
        (members.join("active"), mode),
        (members.join("incoming"), mode),
    ] {
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            expected,
            "{path:?}"
        );
    }
    let saved = members.join(format!("incoming/{BOB_MEMBER_HANDLE}.json"));
    if kind == WorkspaceKind::Global {
        assert_eq!(
            fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn member_add_retains_global_input_after_the_selected_link_is_replaced() {
    use crate::service::diagnostics::{take_local_state_warnings, DiagnosticCode};
    use crate::service::file::FileInputTarget;
    use crate::service::workspace::WorkspaceCreationTarget;
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (_source_home, source) = setup_test_workspace_from_fixtures(&[BOB_MEMBER_HANDLE]);
    let (_destination_home, destination) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key = source
        .join("members/active")
        .join(format!("{BOB_MEMBER_HANDLE}.json"));
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    let selected = source.join("public-key.json");
    symlink(&key, &selected).unwrap();
    let global = WorkspaceCreationTarget::open(&source, WorkspaceKind::Global).unwrap();
    take_local_state_warnings();
    let input = FileInputTarget::open(&selected, Some(&global)).unwrap();
    fs::remove_file(&selected).unwrap();
    fs::write(&selected, "invalid replacement").unwrap();
    let workspace = WorkspaceAccess::open(&destination, WorkspaceKind::Regular).unwrap();
    assert_eq!(
        super::add_member(&workspace, &input, false).unwrap(),
        BOB_MEMBER_HANDLE
    );
    assert!(destination
        .join("members/incoming")
        .join(format!("{BOB_MEMBER_HANDLE}.json"))
        .is_file());
    assert!(take_local_state_warnings()
        .diagnostics()
        .iter()
        .any(
            |finding| finding.code() == DiagnosticCode::GlobalWorkspacePermissions
                && finding.path() == selected
        ));
}

#[test]
fn member_removal_uses_the_selected_workspace_after_root_replacement() {
    use crate::service::workspace::{WorkspaceAccess, WorkspaceKind};
    let (_home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let access = WorkspaceAccess::open(&workspace, WorkspaceKind::Global).unwrap();
    let moved = workspace.with_extension("retained");
    fs::rename(&workspace, &moved).unwrap();
    fs::create_dir(&workspace).unwrap();
    let report = evaluate_member_removal(&access, BOB_MEMBER_HANDLE, false).unwrap();
    assert_eq!(report.member_handle, BOB_MEMBER_HANDLE);
    remove_member(&report).unwrap();
    assert_eq!(load_active_member_files(&moved).unwrap().len(), 1);
}

fn build_verified_members(
    temp_dir: &TempDir,
    recipient_handles: &[&str],
) -> (
    crate::feature::context::crypto::CryptoContext,
    String,
    Vec<String>,
    Vec<crate::model::public_key::VerifiedRecipientKey>,
    crate::model::public_key::PublicKey,
) {
    let key_ctx = setup_member_key_context(temp_dir, ALICE_MEMBER_HANDLE, None);
    let keystore_root = temp_dir.path().join("keys");
    let signer_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let signer_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &signer_kid).unwrap();
    let recipients = recipient_handles
        .iter()
        .map(|member_handle| (*member_handle).to_string())
        .collect::<Vec<_>>();
    let public_keys = recipient_handles
        .iter()
        .map(|member_handle| {
            let kid = list_kids(&keystore_root, member_handle).unwrap().remove(0);
            load_public_key(&keystore_root, member_handle, &kid).unwrap()
        })
        .collect::<Vec<_>>();

    (
        key_ctx,
        signer_kid,
        recipients,
        build_verified_recipient_keys(&public_keys),
        signer_pub,
    )
}

fn save_file_artifact(
    workspace_dir: &Path,
    temp_dir: &TempDir,
    artifact_name: &str,
    recipient_handles: &[&str],
) {
    let (key_ctx, signer_kid, recipients, verified_members, signer_pub) =
        build_verified_members(temp_dir, recipient_handles);
    let document = encrypt_file_document(
        b"member-remove-preview",
        &recipients,
        &verified_members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &signer_kid,
            signer_pub,
        },
    )
    .unwrap();
    fs::write(
        workspace_dir.join("secrets").join(artifact_name),
        serde_json::to_string_pretty(&document).unwrap(),
    )
    .unwrap();
}

fn save_kv_artifact(
    workspace_dir: &Path,
    temp_dir: &TempDir,
    artifact_name: &str,
    recipient_handles: &[&str],
) {
    let (key_ctx, signer_kid, _recipients, verified_members, signer_pub) =
        build_verified_members(temp_dir, recipient_handles);
    let kv_map = HashMap::from([(String::from("API_KEY"), String::from("secret-value"))]);
    let content = encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &signer_kid,
            signer_pub,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();
    fs::write(workspace_dir.join("secrets").join(artifact_name), content).unwrap();
}

fn tamper_file_artifact_signature(workspace_dir: &Path, artifact_name: &str) {
    let artifact_path = workspace_dir.join("secrets").join(artifact_name);
    let mut document: Value =
        serde_json::from_str(&fs::read_to_string(&artifact_path).unwrap()).unwrap();
    document["protected"]["updated_at"] = Value::String("2026-01-01T00:00:01Z".to_string());
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&document).unwrap(),
    )
    .unwrap();
}

#[test]
fn test_evaluate_member_removal_detects_file_enc_recipient() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let artifact_path = workspace_dir.join("secrets").join("shared.json");
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "shared.json",
        &[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE],
    );
    let workspace = WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap();
    let result = evaluate_member_removal(&workspace, BOB_MEMBER_HANDLE, false).unwrap();

    assert_eq!(result.affected_artifacts.len(), 1);
    assert!(result.affected_artifacts[0].ends_with("shared.json"));
    assert_eq!(
        result.affected_artifacts[0].file_name(),
        artifact_path.file_name()
    );
    assert!(result.warnings.is_empty());
}

#[test]
fn test_evaluate_member_removal_detects_kv_enc_recipient() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let artifact_path = workspace_dir.join("secrets").join("default.kvenc");
    save_kv_artifact(
        &workspace_dir,
        &temp_dir,
        "default.kvenc",
        &[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE],
    );
    let workspace = WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap();
    let result = evaluate_member_removal(&workspace, BOB_MEMBER_HANDLE, false).unwrap();

    assert_eq!(result.affected_artifacts.len(), 1);
    assert!(result.affected_artifacts[0].ends_with("default.kvenc"));
    assert_eq!(
        result.affected_artifacts[0].file_name(),
        artifact_path.file_name()
    );
    assert!(result.warnings.is_empty());
}

#[test]
fn test_evaluate_member_removal_ignores_unrelated_artifact() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "alice-only.json",
        &[ALICE_MEMBER_HANDLE],
    );
    let workspace = WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap();
    let result = evaluate_member_removal(&workspace, BOB_MEMBER_HANDLE, false).unwrap();

    assert!(result.affected_artifacts.is_empty());
    assert!(result.warnings.is_empty());
}

#[test]
fn test_remove_member_deletes_active_member_file() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let workspace = WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap();
    let review = evaluate_member_removal(&workspace, BOB_MEMBER_HANDLE, false).unwrap();
    let result = remove_member(&review).unwrap();

    assert_eq!(result.member_handle, BOB_MEMBER_HANDLE);
    let active_member_handles = load_active_member_files(&workspace_dir)
        .unwrap()
        .into_iter()
        .map(|member| member.protected.subject_handle)
        .collect::<Vec<_>>();
    assert_eq!(active_member_handles, vec![ALICE_MEMBER_HANDLE.to_string()]);
}

#[test]
fn test_evaluate_member_removal_collects_warning_for_invalid_artifact() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    fs::write(workspace_dir.join("secrets").join("broken.json"), "{broken").unwrap();
    let workspace = WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap();
    let result = evaluate_member_removal(&workspace, BOB_MEMBER_HANDLE, false).unwrap();

    assert!(result.affected_artifacts.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("broken.json"));
}

#[test]
fn test_evaluate_member_removal_continues_after_tampered_artifact() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "valid.json",
        &[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE],
    );
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "tampered.json",
        &[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE],
    );
    tamper_file_artifact_signature(&workspace_dir, "tampered.json");
    let workspace = WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap();
    let result = evaluate_member_removal(&workspace, BOB_MEMBER_HANDLE, false).unwrap();

    assert_eq!(result.affected_artifacts.len(), 1);
    assert!(result.affected_artifacts[0].ends_with("valid.json"));
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("tampered.json"));
    assert!(result.warnings[0].contains("Signature verification failed"));
}

#[test]
fn test_evaluate_member_removal_collects_warning_for_invalid_signature() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "tampered.json",
        &[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE],
    );
    tamper_file_artifact_signature(&workspace_dir, "tampered.json");
    let workspace = WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap();
    let result = evaluate_member_removal(&workspace, BOB_MEMBER_HANDLE, false).unwrap();

    assert!(result.affected_artifacts.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("tampered.json"));
    assert!(result.warnings[0].contains("Signature verification failed"));
}
