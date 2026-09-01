// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;

use crate::api::key::KeyContext;
use crate::app::context::execution::{resolve_read_trust_evaluator, ExecutionContext};
use crate::app::trust::list::{list_known_keys_command, resolve_trust_list_command};
use crate::app::trust::{
    enforce_policy_strict_key_checking, load_read_trust_context, CommandCapability,
    CommandTrustSnapshot, DecryptPolicy, EncryptPolicy, GetPolicy, ImportPolicy, ListPolicy,
    RewrapInputPolicy, RunPolicy, SetPolicy, UnsetPolicy,
};
use crate::app_test_utils::{
    build_test_command_options, build_test_execution_context, load_test_trust_store,
};
use crate::cli_api::test_support::storage::keystore::member::find_active_key_document;
use crate::cli_api::test_support::storage::trust::store::save_trust_store;
use crate::config::types::{StrictKeyChecking, StrictKeyCheckingResolution};
use crate::feature::trust::judgment::TrustIdentity;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{
    member_handle, save_active_public_key_to_workspace, save_public_key,
    setup_test_keystore_from_fixtures, update_active_private_key_expires_at, EnvGuard,
};

fn open_test_keystore(
    options: &crate::app::context::options::CommonCommandOptions,
) -> KeystoreAccess {
    KeystoreAccess::open(options.resolve_keystore_root().unwrap()).unwrap()
}

fn build_known_key(kid: &str, member_handle: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        subject_handle: member_handle.to_string(),
        approved_at: "2026-01-01T00:00:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

#[test]
fn test_command_trust_snapshot_loads_local_nonactive_self_key() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    let keystore_root = dir.path().join("keys");
    let mut local_nonactive = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key fixture")
        .public_key;
    local_nonactive.protected.kid = "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string();
    local_nonactive.protected.keys.sig.x =
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string();
    save_public_key(
        &keystore_root,
        ALICE_MEMBER_HANDLE,
        &local_nonactive.protected.kid,
        &local_nonactive,
    )
    .unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let execution = build_test_execution_context(&dir, ALICE_MEMBER_HANDLE, Some(&workspace));

    let snapshot = CommandTrustSnapshot::<EncryptPolicy>::load(
        &options,
        &execution,
        &open_test_keystore(&options),
    )
    .unwrap();
    let identity = TrustIdentity::from_public_key(&local_nonactive).unwrap();

    assert!(snapshot
        .trust_context()
        .self_trust
        .contains_identity(&identity)
        .unwrap());
}

#[test]
fn test_command_trust_snapshot_defers_unreferenced_local_self_key_loading() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    let keystore_root = dir.path().join("keys");
    let broken_kid = "KCD3AAAA1111BBBB2222CCCC3333DDDD";
    let broken_dir = keystore_root.join(ALICE_MEMBER_HANDLE).join(broken_kid);
    fs::create_dir_all(&broken_dir).unwrap();
    fs::write(broken_dir.join("public.json"), b"{not-json").unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let execution = build_test_execution_context(&dir, ALICE_MEMBER_HANDLE, Some(&workspace));

    let snapshot = CommandTrustSnapshot::<EncryptPolicy>::load(
        &options,
        &execution,
        &open_test_keystore(&options),
    )
    .unwrap();
    let active = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key fixture");
    let identity = TrustIdentity::from_public_key(&active.public_key).unwrap();

    assert!(snapshot
        .trust_context()
        .self_trust
        .contains_identity(&identity)
        .unwrap());
}

#[test]
fn test_trust_snapshots_keep_self_trust_bound_to_loaded_keystore() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    let keystore_root = dir.path().join("keys");
    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let active = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key fixture");
    let original_identity = TrustIdentity::from_public_key(&active.public_key).unwrap();
    let mut replacement = active.public_key.clone();
    replacement.protected.keys.sig.x = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string();
    let replacement_identity = TrustIdentity::from_public_key(&replacement).unwrap();
    let execution = build_test_execution_context(&dir, ALICE_MEMBER_HANDLE, Some(&workspace));
    let bound_root = dir.path().join("keys.bound");
    fs::rename(&keystore_root, &bound_root).unwrap();
    save_public_key(
        &keystore_root,
        ALICE_MEMBER_HANDLE,
        &replacement.protected.kid,
        &replacement,
    )
    .unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));

    let write = CommandTrustSnapshot::<EncryptPolicy>::load(&options, &execution, &access).unwrap();
    let read = load_read_trust_context(&options, &execution, "encrypt").unwrap();

    for self_trust in [
        &write.trust_context().self_trust,
        &read.trust_ctx.self_trust,
    ] {
        assert!(self_trust.contains_identity(&original_identity).unwrap());
        assert!(!self_trust.contains_identity(&replacement_identity).unwrap());
    }
}

#[test]
fn test_load_read_trust_context_allows_expired_active_member_with_warning() {
    const BOB_MEMBER_HANDLE: &str = "bob@example.com";
    let (dir, workspace) = crate::test_utils::setup_test_workspace_from_fixtures(&[
        ALICE_MEMBER_HANDLE,
        BOB_MEMBER_HANDLE,
    ]);
    update_active_private_key_expires_at(dir.path(), BOB_MEMBER_HANDLE, "2020-01-01T00:00:00Z");
    save_active_public_key_to_workspace(dir.path(), &workspace, BOB_MEMBER_HANDLE).unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let execution = build_test_execution_context(&dir, ALICE_MEMBER_HANDLE, Some(&workspace));

    let loaded = load_read_trust_context(&options, &execution, "decrypt").unwrap();

    assert_eq!(loaded.trust_ctx.active_members_by_kid.len(), 2);
    assert!(loaded
        .warnings
        .iter()
        .any(|warning| warning.contains("expired")));
}

/// The member set a read is authorized against comes from the workspace the
/// execution bound to. A tree swapped in behind the workspace path afterwards
/// holds different members, and the read keeps answering from the one it opened.
#[cfg(unix)]
#[test]
fn test_read_trust_context_keeps_the_member_set_of_the_bound_workspace() {
    const BOB_MEMBER_HANDLE: &str = "bob@example.com";
    let (dir, workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let (_replacement_dir, replacement) = crate::test_utils::setup_test_workspace_from_fixtures(&[
        ALICE_MEMBER_HANDLE,
        BOB_MEMBER_HANDLE,
    ]);
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let execution = build_test_execution_context(&dir, ALICE_MEMBER_HANDLE, Some(&workspace));
    let opened_workspace = workspace.with_extension("opened");
    fs::rename(&workspace, &opened_workspace).unwrap();
    fs::rename(&replacement, &workspace).unwrap();

    let loaded = load_read_trust_context(&options, &execution, "decrypt").unwrap();

    assert_eq!(loaded.trust_ctx.active_members_by_kid.len(), 1);
}

/// The member set a write plans against comes from the workspace the execution
/// bound to. A tree swapped in behind the workspace path afterwards holds
/// different members, and the plan keeps recipients from the one it opened.
#[cfg(unix)]
#[test]
fn test_write_trust_snapshot_keeps_the_member_set_of_the_bound_workspace() {
    const BOB_MEMBER_HANDLE: &str = "bob@example.com";
    let (dir, workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let (_replacement_dir, replacement) = crate::test_utils::setup_test_workspace_from_fixtures(&[
        ALICE_MEMBER_HANDLE,
        BOB_MEMBER_HANDLE,
    ]);
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let execution = build_test_execution_context(&dir, ALICE_MEMBER_HANDLE, Some(&workspace));
    let opened_workspace = workspace.with_extension("opened");
    fs::rename(&workspace, &opened_workspace).unwrap();
    fs::rename(&replacement, &workspace).unwrap();

    let snapshot = CommandTrustSnapshot::<EncryptPolicy>::load(
        &options,
        &execution,
        &open_test_keystore(&options),
    )
    .unwrap();

    assert_eq!(snapshot.workspace_members().active_members().len(), 1);
}

#[test]
fn test_write_trust_snapshot_rejects_expired_active_member() {
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    update_active_private_key_expires_at(dir.path(), ALICE_MEMBER_HANDLE, "2020-01-01T00:00:00Z");
    save_active_public_key_to_workspace(dir.path(), &workspace, ALICE_MEMBER_HANDLE).unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let execution = build_test_execution_context(&dir, ALICE_MEMBER_HANDLE, Some(&workspace));

    let error = CommandTrustSnapshot::<EncryptPolicy>::load(
        &options,
        &execution,
        &open_test_keystore(&options),
    )
    .unwrap_err();

    assert!(error.to_string().contains("expired"));
}

#[test]
fn test_non_member_acceptance_allowed_commands() {
    assert!(CommandCapability::Decrypt.allows_non_member_acceptance());
    assert!(CommandCapability::Get.allows_non_member_acceptance());
    assert!(CommandCapability::List.allows_non_member_acceptance());
    assert!(CommandCapability::Rewrap.allows_non_member_acceptance());
}

#[test]
fn test_non_member_acceptance_forbidden_commands() {
    assert!(!CommandCapability::Run.allows_non_member_acceptance());
    assert!(!CommandCapability::Set.allows_non_member_acceptance());
    assert!(!CommandCapability::Unset.allows_non_member_acceptance());
    assert!(!CommandCapability::Import.allows_non_member_acceptance());
}

#[test]
fn test_policy_strict_key_checking_no_allowed_for_read_paths() {
    assert!(CommandCapability::Decrypt.allows_strict_key_checking_no());
    assert!(CommandCapability::Get.allows_strict_key_checking_no());
    assert!(CommandCapability::List.allows_strict_key_checking_no());
    assert!(CommandCapability::Run.allows_strict_key_checking_no());
    let strict_no = StrictKeyCheckingResolution::explicit(StrictKeyChecking::No);

    enforce_policy_strict_key_checking::<DecryptPolicy>(strict_no).unwrap();
    enforce_policy_strict_key_checking::<GetPolicy>(strict_no).unwrap();
    enforce_policy_strict_key_checking::<ListPolicy>(strict_no).unwrap();
    enforce_policy_strict_key_checking::<RunPolicy>(strict_no).unwrap();
}

#[test]
fn test_policy_strict_key_checking_no_rejected_for_write_paths_and_rewrap() {
    assert!(!CommandCapability::Encrypt.allows_strict_key_checking_no());
    assert!(!CommandCapability::Set.allows_strict_key_checking_no());
    assert!(!CommandCapability::Unset.allows_strict_key_checking_no());
    assert!(!CommandCapability::Import.allows_strict_key_checking_no());
    assert!(!CommandCapability::Rewrap.allows_strict_key_checking_no());
    let strict_no = StrictKeyCheckingResolution::explicit(StrictKeyChecking::No);

    assert!(enforce_policy_strict_key_checking::<EncryptPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<SetPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<UnsetPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<ImportPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<RewrapInputPolicy>(strict_no).is_err());
}

#[test]
fn test_env_key_mode_allowed_commands() {
    assert!(CommandCapability::Decrypt.allows_env_key_mode());
    assert!(CommandCapability::Doctor.allows_env_key_mode());
    assert!(CommandCapability::Get.allows_env_key_mode());
    assert!(CommandCapability::List.allows_env_key_mode());
    assert!(CommandCapability::Run.allows_env_key_mode());
}

#[test]
fn test_env_key_mode_rejected_for_mutating_and_management_commands() {
    for capability in [
        CommandCapability::Config,
        CommandCapability::Encrypt,
        CommandCapability::Import,
        CommandCapability::Init,
        CommandCapability::Inspect,
        CommandCapability::Join,
        CommandCapability::Key,
        CommandCapability::Member,
        CommandCapability::Rewrap,
        CommandCapability::Set,
        CommandCapability::Trust,
        CommandCapability::Unset,
    ] {
        assert!(
            !capability.allows_env_key_mode(),
            "{} should not be available in env key mode",
            capability.label()
        );
    }
}

#[test]
fn test_env_key_mode_allowed_commands_exclude_write_paths() {
    assert!(!CommandCapability::Encrypt.allows_env_key_mode());
    assert!(!CommandCapability::Init.allows_env_key_mode());
    assert!(!CommandCapability::Set.allows_env_key_mode());
    assert!(!CommandCapability::Trust.allows_env_key_mode());
}

#[test]
fn test_trust_list_no_trust_store_returns_empty() {
    let dir = tempfile::TempDir::new().unwrap();
    let options = build_test_command_options(dir.path(), None);

    let command =
        resolve_trust_list_command(&options, Some("nobody@example.com".to_string())).unwrap();
    let result = list_known_keys_command(&command).unwrap();

    assert!(result.items.is_empty());
}

#[cfg(unix)]
#[test]
fn test_optional_read_trust_surfaces_existing_document_error_without_keystore() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::TempDir::new().unwrap();
    let trust_dir = dir.path().join("trust");
    fs::create_dir(&trust_dir).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&trust_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let trust_path = get_trust_store_file_path(dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::write(&trust_path, "{invalid-json").unwrap();
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o600)).unwrap();
    let options = build_test_command_options(dir.path(), None);

    let error = match load_test_trust_store(&options, ALICE_MEMBER_HANDLE) {
        Err(error) => error,
        Ok(_) => panic!("expected invalid trust store error"),
    };

    assert_eq!(error.kind(), crate::ErrorKind::Parse);
    assert_eq!(error.recovery(), Some("E_TRUST_STORE_RESET_REQUIRED"));
    assert!(error.to_string().contains("invalid and must be reset"));
}

#[cfg(unix)]
#[test]
fn test_optional_read_trust_reports_missing_local_keystore() {
    let (dir, _workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = crate::test_utils::setup_member_key_context(&dir, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let trust_path = get_trust_store_file_path(dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    save_trust_store(&trust_path, &document).unwrap();
    fs::remove_dir_all(dir.path().join("keys")).unwrap();
    let options = build_test_command_options(dir.path(), None);

    let error = match load_test_trust_store(&options, ALICE_MEMBER_HANDLE) {
        Err(error) => error,
        Ok(_) => panic!("a trust document without a verification keystore must fail"),
    };

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
    assert!(error
        .format_user_message()
        .contains(&dir.path().join("keys").display().to_string()));
    assert!(error.format_user_message().contains("--home"));
    assert!(error.format_user_message().contains("KAPSARO_HOME"));
}

#[test]
fn test_optional_read_trust_reports_missing_signer_key() {
    let (dir, _workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = crate::test_utils::setup_member_key_context(&dir, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let signer_kid = document.signature.kid.clone();
    let trust_path = get_trust_store_file_path(dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    save_trust_store(&trust_path, &document).unwrap();
    fs::remove_file(
        dir.path()
            .join("keys")
            .join(ALICE_MEMBER_HANDLE)
            .join(&signer_kid)
            .join("public.json"),
    )
    .unwrap();
    let options = build_test_command_options(dir.path(), None);

    let error = match load_test_trust_store(&options, ALICE_MEMBER_HANDLE) {
        Err(error) => error,
        Ok(_) => panic!("a trust document without its signer key must fail verification"),
    };

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_TRUST_SIGNER_KEY_MISSING"));
    assert!(error.format_user_message().contains(&signer_kid));
}

#[test]
fn test_optional_read_trust_verifies_existing_document_from_fixed_home() {
    let (dir, _workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = crate::test_utils::setup_member_key_context(&dir, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let trust_path = get_trust_store_file_path(dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    save_trust_store(&trust_path, &document).unwrap();
    let options = build_test_command_options(dir.path(), None);

    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE).unwrap();

    assert_eq!(loaded.unwrap().protected.owner_handle, ALICE_MEMBER_HANDLE);
}

#[test]
fn test_env_key_read_evaluator_verifies_existing_local_trust_store() {
    let (dir, workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let local_key_ctx =
        crate::test_utils::setup_member_key_context(&dir, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document =
        sign_trust_store(&protected, local_key_ctx.signing_key(), local_key_ctx.kid()).unwrap();
    let trust_path = get_trust_store_file_path(dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    save_trust_store(&trust_path, &document).unwrap();
    let env_key_ctx = local_key_ctx.with_local_key_access(None, None);
    let execution = ExecutionContext::from_test_parts(
        member_handle(ALICE_MEMBER_HANDLE),
        KeyContext::from_inner(env_key_ctx),
        Some(WorkspaceRoot {
            root_path: workspace.clone(),
        }),
        Some(dir.path().to_path_buf()),
    )
    .unwrap();
    resolve_read_trust_evaluator(&execution).unwrap();
}

/// In environment key mode there is no local keystore capability, so the fixed
/// local state home is what binds the read to one trust store.
#[cfg(unix)]
#[test]
fn test_env_key_read_trust_context_reads_the_fixed_home_after_path_swap() {
    let (dir, workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let (replacement, _) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let local_key_ctx =
        crate::test_utils::setup_member_key_context(&dir, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: vec![build_known_key(local_key_ctx.kid(), ALICE_MEMBER_HANDLE)],
        recipient_sets: Vec::new(),
    };
    let document =
        sign_trust_store(&protected, local_key_ctx.signing_key(), local_key_ctx.kid()).unwrap();
    save_trust_store(
        &get_trust_store_file_path(dir.path(), &member_handle(ALICE_MEMBER_HANDLE)),
        &document,
    )
    .unwrap();
    let env_key_ctx = local_key_ctx.with_local_key_access(None, None);
    let execution = ExecutionContext::from_test_parts(
        member_handle(ALICE_MEMBER_HANDLE),
        KeyContext::from_inner(env_key_ctx),
        Some(WorkspaceRoot {
            root_path: workspace.clone(),
        }),
        Some(dir.path().to_path_buf()),
    )
    .unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let opened_home = dir.path().with_extension("opened");
    fs::rename(dir.path(), &opened_home).unwrap();
    fs::rename(replacement.path(), dir.path()).unwrap();

    let loaded = load_read_trust_context(&options, &execution, "decrypt").unwrap();

    assert_eq!(loaded.trust_ctx.known_keys.len(), 1);
    assert_eq!(
        loaded.trust_ctx.known_keys[0].subject_handle,
        ALICE_MEMBER_HANDLE
    );

    drop(execution);
    fs::rename(dir.path(), replacement.path()).unwrap();
    fs::rename(&opened_home, dir.path()).unwrap();
}

#[cfg(unix)]
#[test]
fn test_trust_list_warns_about_insecure_permission() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, _workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&["alice@example.com"]);
    let owner_handle = "alice@example.com";
    let key_ctx = crate::test_utils::setup_member_key_context(&dir, owner_handle, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: vec![build_known_key(key_ctx.kid(), owner_handle)],
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let trust_path = get_trust_store_file_path(dir.path(), &member_handle(owner_handle));
    save_trust_store(&trust_path, &document).unwrap();
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let options = build_test_command_options(dir.path(), None);

    let command = resolve_trust_list_command(&options, Some(owner_handle.to_string())).unwrap();

    let warning_guard = LocalStateWarningGuard::new();
    let listed = list_known_keys_command(&command).unwrap();
    let warnings = warning_guard.take_reasons();

    assert_eq!(listed.items.len(), 1);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0644"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("chmod 0600"), "{warnings:?}");
}

#[test]
fn test_env_key_read_evaluator_reports_missing_local_keystore() {
    let (dir, workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let local_key_ctx =
        crate::test_utils::setup_member_key_context(&dir, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document =
        sign_trust_store(&protected, local_key_ctx.signing_key(), local_key_ctx.kid()).unwrap();
    let trust_path = get_trust_store_file_path(dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    save_trust_store(&trust_path, &document).unwrap();
    let env_key_ctx = local_key_ctx.with_local_key_access(None, None);
    let execution = ExecutionContext::from_test_parts(
        member_handle(ALICE_MEMBER_HANDLE),
        KeyContext::from_inner(env_key_ctx),
        Some(WorkspaceRoot {
            root_path: workspace.clone(),
        }),
        Some(dir.path().to_path_buf()),
    )
    .unwrap();
    fs::remove_dir_all(dir.path().join("keys")).unwrap();

    let error = match resolve_read_trust_evaluator(&execution) {
        Err(error) => error,
        Ok(_) => panic!("a trust document without a verification keystore must fail"),
    };

    assert_eq!(error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
}
