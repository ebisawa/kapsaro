// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::kv::mutation::{
    resolve_mutation_write_plan, set_kv_command, MutationWriteTrustPlan,
};
use crate::app::trust::SetPolicy;
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_ssh_context};
use crate::feature::kv::types::KvInputEntry;
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::storage::list_kids;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
    update_active_private_key_expires_at, with_temp_cwd, EnvGuard,
};
use std::fs;

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

fn evaluate_set_plan(
    options: &CommonCommandOptions,
    name: Option<&str>,
) -> MutationWriteTrustPlan<SetPolicy> {
    let ssh_ctx = Some(resolve_test_ssh_context(options, ALICE_MEMBER_HANDLE));
    resolve_mutation_write_plan::<SetPolicy>(
        options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        name,
        true,
        ssh_ctx,
    )
    .unwrap()
}

fn activate_fixture_key(home: &std::path::Path) {
    let keystore_root = home.join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
}

#[test]
fn test_execute_set_rejects_existing_file_mismatch_after_review() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let initial = evaluate_set_plan(&options, None);
        set_kv_command(&initial, vec![KvInputEntry::new("KEY1", "value1")], None).unwrap();

        let reviewed = evaluate_set_plan(&options, None);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        fs::write(&kv_path, ":SECRETENV_KV 4\n:HEAD {}\n:WRAP {}\n").unwrap();

        let result = set_kv_command(&reviewed, vec![KvInputEntry::new("KEY2", "value2")], None);

        match result {
            Err(err) => assert!(err.to_string().contains("changed since review")),
            Ok(_) => panic!("expected mismatch error"),
        }
        assert_eq!(
            fs::read_to_string(&kv_path).unwrap(),
            ":SECRETENV_KV 4\n:HEAD {}\n:WRAP {}\n"
        );
    });
}

#[test]
fn test_execute_set_rejects_file_created_after_missing_review() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let reviewed = evaluate_set_plan(&options, Some("later"));
        let kv_path = workspace_dir.join("secrets").join("later.kvenc");
        fs::write(&kv_path, "external-content").unwrap();

        let result = set_kv_command(&reviewed, vec![KvInputEntry::new("KEY1", "value1")], None);

        match result {
            Err(err) => assert!(err.to_string().contains("changed since review")),
            Ok(_) => panic!("expected mismatch error"),
        }
        assert_eq!(fs::read_to_string(&kv_path).unwrap(), "external-content");
    });
}

#[cfg(unix)]
#[test]
fn test_execute_set_rejects_symlinked_existing_file_after_review() {
    use std::os::unix::fs::symlink;

    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let initial = evaluate_set_plan(&options, None);
        set_kv_command(&initial, vec![KvInputEntry::new("KEY1", "value1")], None).unwrap();

        let reviewed = evaluate_set_plan(&options, None);
        let kv_path = workspace_dir.join("secrets").join("default.kvenc");
        let reviewed_content = fs::read_to_string(&kv_path).unwrap();
        let victim_path = workspace_dir.join("victim.kvenc");
        fs::write(&victim_path, &reviewed_content).unwrap();
        fs::remove_file(&kv_path).unwrap();
        symlink(&victim_path, &kv_path).unwrap();

        let result = set_kv_command(&reviewed, vec![KvInputEntry::new("KEY2", "value2")], None);

        match result {
            Err(err) => assert!(err.to_string().contains("changed since review")),
            Ok(_) => panic!("expected mismatch error"),
        }
        assert_eq!(fs::read_to_string(&victim_path).unwrap(), reviewed_content);
    });
}

#[test]
fn test_execute_set_rejects_active_member_snapshot_change_after_review() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let reviewed = evaluate_set_plan(&options, None);
        let bob_active = workspace_dir
            .join("members")
            .join("active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        let bob_incoming = workspace_dir
            .join("members")
            .join("incoming")
            .join(format!("{}.json", BOB_MEMBER_HANDLE));
        fs::rename(&bob_active, &bob_incoming).unwrap();

        let result = set_kv_command(&reviewed, vec![KvInputEntry::new("KEY1", "value1")], None);

        match result {
            Err(err) => assert!(err
                .to_string()
                .contains("active members changed since review")),
            Ok(_) => panic!("expected active member snapshot mismatch error"),
        }
    });
}

#[test]
fn test_evaluate_set_rejects_strict_key_checking_no_for_existing_file() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);

    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let initial = evaluate_set_plan(&options, None);
        set_kv_command(&initial, vec![KvInputEntry::new("KEY1", "value1")], None).unwrap();
        std::env::set_var("SECRETENV_STRICT_KEY_CHECKING", "no");

        let ssh_ctx = Some(resolve_test_ssh_context(&options, ALICE_MEMBER_HANDLE));
        let result = resolve_mutation_write_plan::<SetPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            true,
            ssh_ctx,
        );

        match result {
            Err(err) => assert!(err.to_string().contains("not allowed")),
            Ok(_) => panic!("expected strict key checking error"),
        }
    });
}

#[cfg(unix)]
#[test]
fn test_evaluate_kv_write_trust_surfaces_insecure_trust_store_warning() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_HANDLE);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    with_temp_cwd(temp_dir.path(), || {
        let plan = evaluate_set_plan(&options, None);
        assert!(!plan.warnings.is_empty());
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("Insecure permissions")));
    });
}

#[test]
fn test_resolve_mutation_write_plan_includes_private_key_expiry_warning() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);

    with_temp_cwd(temp_dir.path(), || {
        let plan = evaluate_set_plan(&options, None);
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("Private key expires in")));
    });
}

#[test]
fn test_resolve_mutation_write_plan_includes_recipient_key_expiry_warning() {
    let _guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_HANDLE)
        .unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    with_temp_cwd(temp_dir.path(), || {
        let plan = evaluate_set_plan(&options, None);
        assert!(plan.warnings.iter().any(
            |warning| warning.contains("Recipient public key for 'bob@example.com' expires in")
        ));
    });
}
