// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::cli::common::{run_command_with_pty, secretenv_bin};
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace_incoming,
    setup_member_key_context, setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
    update_active_private_key_expires_at,
};
use secretenv::feature::key::public_key_document::{build_public_key, PublicKeyDocumentParams};
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::storage::list_kids;
use secretenv::io::trust::paths::get_trust_store_file_path;
use secretenv::io::workspace::members::load_member_file_from_path;
use secretenv::model::public_key::GithubAccount;
use secretenv::support::tty;
#[cfg(unix)]
use std::process::Command as StdCommand;

fn rewrite_member_with_github_binding(
    temp_dir: &tempfile::TempDir,
    member_file: &std::path::Path,
    member_id: &str,
    id: u64,
    login: &str,
) {
    let key_ctx = setup_member_key_context(temp_dir, member_id, None);
    let existing = load_member_file_from_path(member_file).unwrap();
    let created_at = existing.protected.created_at.clone().unwrap();
    let expires_at = existing.protected.expires_at.clone();
    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_id,
        identity: existing.protected.identity,
        created_at: &created_at,
        expires_at: &expires_at,
        sig_sk: &key_ctx.signing_key,
        debug: false,
        github_account: Some(GithubAccount {
            id,
            login: login.to_string(),
        }),
    })
    .unwrap();
    fs::write(
        member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();
}

fn rewrite_member_with_foreign_identity(
    temp_dir: &tempfile::TempDir,
    source_member_file: &std::path::Path,
    target_member_file: &std::path::Path,
    target_member_id: &str,
    signer_member_id: &str,
) {
    let key_ctx = setup_member_key_context(temp_dir, signer_member_id, None);
    let source = load_member_file_from_path(source_member_file).unwrap();
    let created_at = source.protected.created_at.clone().unwrap();
    let expires_at = source.protected.expires_at.clone();
    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_id: target_member_id,
        identity: source.protected.identity,
        created_at: &created_at,
        expires_at: &expires_at,
        sig_sk: &key_ctx.signing_key,
        debug: false,
        github_account: None,
    })
    .unwrap();
    fs::write(
        target_member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();
}

#[test]
fn test_rewrap_adds_new_member() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let bob_member_file = workspace_dir
        .join("members/active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_member_content = fs::read_to_string(&bob_member_file).unwrap();
    fs::remove_file(&bob_member_file).unwrap();

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "test_add",
        &[("KEY", "value")],
    );

    fs::write(&bob_member_file, bob_member_content).unwrap();

    let rids_before = load_kv_rids(&kv_path);
    assert!(
        !rids_before.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should not be in wrap before rewrap"
    );

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    let result = rewrap::run(rewrap_args);
    assert!(result.is_ok(), "Rewrap should succeed: {:?}", result.err());

    let rids_after = load_kv_rids(&kv_path);
    assert!(
        rids_after.contains(&ALICE_MEMBER_ID.to_string()),
        "ALICE should still be in wrap after rewrap"
    );
    assert!(
        rids_after.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should be added to wrap after rewrap"
    );
}

#[test]
fn test_rewrap_non_interactive_skips_prompt_for_known_incoming_kid() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "known_incoming",
        &[("KEY", "value")],
    );

    let result = rewrap::run(default_rewrap_args(common_opts, ALICE_MEMBER_ID));

    assert!(
        result.is_ok(),
        "Rewrap should succeed without TOFU prompt for known incoming kid: {:?}",
        result.err()
    );
    let rids_after = load_kv_rids(&kv_path);
    assert!(rids_after.contains(&BOB_MEMBER_ID.to_string()));
}

#[test]
fn test_rewrap_non_interactive_skips_online_verify_for_known_incoming_github_binding() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    rewrite_member_with_github_binding(
        &temp_dir,
        &bob_active,
        BOB_MEMBER_ID,
        999999,
        "offline-test-user",
    );

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "known_incoming_binding",
        &[("KEY", "value")],
    );

    let result = rewrap::run(default_rewrap_args(common_opts, ALICE_MEMBER_ID));

    assert!(
        result.is_ok(),
        "Rewrap should succeed without online verify for known incoming kid: {:?}",
        result.err()
    );
    let rids_after = load_kv_rids(&kv_path);
    assert!(rids_after.contains(&BOB_MEMBER_ID.to_string()));
}

#[test]
fn test_rewrap_non_interactive_auto_accepts_self_rotation() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_ID,
        &old_key_ctx,
    );

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "self_rotation",
        &[("KEY", "value")],
    );
    let before = load_kv_rids(&kv_path);
    assert_eq!(before, vec![ALICE_MEMBER_ID.to_string()]);

    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_ID,
        &build_expiring_soon_timestamp(365),
    );
    save_active_public_key_to_workspace_incoming(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID)
        .unwrap();

    tty::set_interactive_override(Some(false));
    let result = rewrap::run(default_rewrap_args(common_opts, ALICE_MEMBER_ID));
    tty::set_interactive_override(None);

    assert!(
        result.is_ok(),
        "Rewrap should auto-accept self rotation in non-interactive mode: {:?}",
        result.err()
    );
    let after = load_kv_rids(&kv_path);
    assert_eq!(after, vec![ALICE_MEMBER_ID.to_string()]);
}

#[cfg(unix)]
#[test]
fn test_rewrap_accept_prompt_accepts_carriage_return_in_pty() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);
    let alice_kid = list_kids(&temp_dir.path().join("keys"), ALICE_MEMBER_ID)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_ID, &alice_kid, &temp_dir.path().join("keys")).unwrap();

    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "pty_accept",
        &[("KEY", "value")],
    );

    let mut command = StdCommand::new(secretenv_bin());
    command
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env(
            "SECRETENV_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        )
        .env("SECRETENV_SSH_SIGNING_METHOD", "ssh-keygen")
        .env_remove("CI");

    let result = run_command_with_pty(&mut command, "Accept?", b"y\r");

    assert!(
        result.status.success(),
        "interactive rewrap should succeed after carriage return input\n{}",
        result.output
    );
    assert!(
        result.output.contains("Accept?"),
        "interactive output should include Accept prompt\n{}",
        result.output
    );
    assert!(
        !result.output.contains("^M"),
        "interactive output should not echo literal carriage-return markers\n{}",
        result.output
    );

    let rids_after = load_kv_rids(&kv_path);
    assert!(
        rids_after.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should be added after interactive PTY acceptance"
    );
}

#[test]
fn test_rewrap_rejects_self_incoming_when_local_identity_mismatches() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let _kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "self_mismatch",
        &[("KEY", "value")],
    );

    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let alice_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", ALICE_MEMBER_ID));
    rewrite_member_with_foreign_identity(
        &temp_dir,
        &bob_active,
        &alice_incoming,
        ALICE_MEMBER_ID,
        BOB_MEMBER_ID,
    );

    tty::set_interactive_override(Some(false));
    let result = rewrap::run(default_rewrap_args(common_opts, ALICE_MEMBER_ID));
    tty::set_interactive_override(None);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_REWRAP_SELF_PROMOTION_MISMATCH"));
}

#[test]
fn test_rewrap_removes_member_kv_enc() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "test_remove",
        &[("KEY", "value")],
    );

    let rids_before = load_kv_rids(&kv_path);
    assert!(rids_before.contains(&ALICE_MEMBER_ID.to_string()));
    assert!(rids_before.contains(&BOB_MEMBER_ID.to_string()));

    fs::remove_file(
        workspace_dir
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_ID)),
    )
    .unwrap();

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    let result = rewrap::run(rewrap_args);
    assert!(result.is_ok(), "Rewrap should succeed: {:?}", result.err());

    let rids_after = load_kv_rids(&kv_path);
    assert!(
        rids_after.contains(&ALICE_MEMBER_ID.to_string()),
        "ALICE should still be in wrap"
    );
    assert!(
        !rids_after.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should be removed from wrap"
    );

    let removed = load_kv_removed_rids(&kv_path);
    assert!(
        removed.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should be in removed_recipients: {:?}",
        removed
    );
}

#[test]
fn test_rewrap_removes_member_file_enc() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);

    // Set up trust store before encrypt/rewrap
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let input_path = workspace_dir.join("test_file_remove.bin");
    fs::write(&input_path, b"binary content").unwrap();
    let encrypted_path = workspace_dir.join("secrets").join("test_file_remove.json");
    let encrypt_args = encrypt::EncryptArgs {
        common: common_opts.clone(),
        member_handle: Some(ALICE_MEMBER_ID.to_string()),
        out: Some(encrypted_path.clone()),
        stdout: false,
        stdin: false,
        input: Some(input_path),
    };
    encrypt::run(encrypt_args).unwrap();
    assert!(encrypted_path.exists(), "Encrypted file should exist");

    fs::remove_file(
        workspace_dir
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_ID)),
    )
    .unwrap();

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    let result = rewrap::run(rewrap_args);
    assert!(result.is_ok(), "Rewrap should succeed: {:?}", result.err());

    let content = fs::read_to_string(&encrypted_path).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
    let wrap = doc["protected"]["wrap"].as_array().unwrap();
    let rids: Vec<&str> = wrap.iter().filter_map(|w| w["rid"].as_str()).collect();
    assert!(
        rids.contains(&ALICE_MEMBER_ID),
        "ALICE should still be in wrap"
    );
    assert!(
        !rids.contains(&BOB_MEMBER_ID),
        "BOB should be removed from wrap"
    );

    let removed = doc["protected"]["removed_recipients"].as_array();
    assert!(removed.is_some(), "removed_recipients should be present");
    let removed_rids: Vec<&str> = removed
        .unwrap()
        .iter()
        .filter_map(|r| r["rid"].as_str())
        .collect();
    assert!(
        removed_rids.contains(&BOB_MEMBER_ID),
        "BOB should be in removed_recipients: {:?}",
        removed_rids
    );
}

#[test]
fn test_rewrap_multiple_files() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path1 = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "multi1",
        &[("KEY1", "value1")],
    );
    let kv_path2 = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "multi2",
        &[("KEY2", "value2")],
    );

    assert!(kv_path1.exists(), "First kv file should exist");
    assert!(kv_path2.exists(), "Second kv file should exist");

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    let result = rewrap::run(rewrap_args);
    assert!(
        result.is_ok(),
        "Rewrap should succeed for multiple files: {:?}",
        result.err()
    );

    assert!(
        kv_path1.exists(),
        "First kv file should still exist after rewrap"
    );
    assert!(
        kv_path2.exists(),
        "Second kv file should still exist after rewrap"
    );

    let rids1 = load_kv_rids(&kv_path1);
    let rids2 = load_kv_rids(&kv_path2);
    assert!(
        rids1.contains(&ALICE_MEMBER_ID.to_string()),
        "ALICE should be in first file's wrap"
    );
    assert!(
        rids2.contains(&ALICE_MEMBER_ID.to_string()),
        "ALICE should be in second file's wrap"
    );
}

#[test]
fn test_rewrap_requires_recipient_trust_approval() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let _kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "trust_gate",
        &[("KEY", "value")],
    );

    fs::remove_file(get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID)).unwrap();

    tty::set_interactive_override(Some(false));
    let result = rewrap::run(default_rewrap_args(common_opts, ALICE_MEMBER_ID));
    tty::set_interactive_override(None);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unknown recipient kid"));
}

#[test]
fn test_rewrap_rejects_duplicate_kid_workspace_before_processing() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let _kv_path = save_kv_file(
        &workspace_dir,
        common_opts,
        ALICE_MEMBER_ID,
        "duplicate_workspace",
        &[("KEY", "value")],
    );
    fs::copy(
        workspace_dir
            .join("members")
            .join("active")
            .join(format!("{}.json", BOB_MEMBER_ID)),
        workspace_dir
            .join("members")
            .join("incoming")
            .join(format!("{}.json", BOB_MEMBER_ID)),
    )
    .unwrap();

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env(
            "SECRETENV_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("Duplicate kid"));
}
