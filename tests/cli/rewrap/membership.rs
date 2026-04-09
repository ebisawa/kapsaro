// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{setup_member_key_context, setup_trust_store_for_workspace};
use secretenv::feature::key::public_key_document::{build_public_key, PublicKeyBuildParams};
use secretenv::io::trust::paths::trust_store_file_path;
use secretenv::io::workspace::members::load_member_file_from_path;
use secretenv::model::public_key::GithubAccount;
use secretenv::support::tty;

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
    let public_key = build_public_key(&PublicKeyBuildParams {
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

    let kv_path = create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "test_add",
        &[("KEY", "value")],
    );

    fs::write(&bob_member_file, bob_member_content).unwrap();

    let rids_before = get_kv_rids(&kv_path);
    assert!(
        !rids_before.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should not be in wrap before rewrap"
    );

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    let result = rewrap::run(rewrap_args);
    assert!(result.is_ok(), "Rewrap should succeed: {:?}", result.err());

    let rids_after = get_kv_rids(&kv_path);
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

    let kv_path = create_kv_file(
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
    let rids_after = get_kv_rids(&kv_path);
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

    let kv_path = create_kv_file(
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
    let rids_after = get_kv_rids(&kv_path);
    assert!(rids_after.contains(&BOB_MEMBER_ID.to_string()));
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

    let kv_path = create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "test_remove",
        &[("KEY", "value")],
    );

    let rids_before = get_kv_rids(&kv_path);
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

    let rids_after = get_kv_rids(&kv_path);
    assert!(
        rids_after.contains(&ALICE_MEMBER_ID.to_string()),
        "ALICE should still be in wrap"
    );
    assert!(
        !rids_after.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should be removed from wrap"
    );

    let removed = get_kv_removed_rids(&kv_path);
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
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        input: input_path,
        out: Some(encrypted_path.clone()),
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

    let kv_path1 = create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "multi1",
        &[("KEY1", "value1")],
    );
    let kv_path2 = create_kv_file(
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

    let rids1 = get_kv_rids(&kv_path1);
    let rids2 = get_kv_rids(&kv_path2);
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

    let _kv_path = create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "trust_gate",
        &[("KEY", "value")],
    );

    fs::remove_file(trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID)).unwrap();

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

    let _kv_path = create_kv_file(
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
        .env("SECRETENV_HOME", temp_dir.path())
        .env(
            "SECRETENV_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("Duplicate kid"));
}
