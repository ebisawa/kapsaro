// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::setup_trust_store_for_workspace;
use kapsaro_test_support::crypto_context::setup_member_key_context;

#[test]
fn test_rewrap_rotate_key() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let _kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "test_rotate",
        &[("KEY", "value")],
    );

    run_rewrap_with_member_set_review_args(&common_opts, ALICE_MEMBER_HANDLE, &["--rotate-key"]);
}

/// A target named without a directory resolves against the working directory,
/// so the rewrite has to reach the entry the read came from.
#[test]
fn test_rewrap_accepts_a_target_named_without_a_directory() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let artifact = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "bare_target",
        &[("KEY", "value")],
    );
    let secrets_dir = artifact
        .parent()
        .expect("saved artifact must sit in a directory")
        .to_path_buf();
    let file_name = artifact
        .file_name()
        .and_then(|name| name.to_str())
        .expect("saved artifact must have a usable name")
        .to_string();

    let mut command = crate::cli::common::kapsaro_std_cmd();
    command
        .arg("rewrap")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE);
    append_common_command_args(&mut command, &common_opts);
    command
        .arg("--rotate-key")
        .arg("--target")
        .arg(&file_name)
        .current_dir(&secrets_dir);
    crate::cli::common::assert_member_set_review_success(&mut command);
}

#[test]
fn test_rewrap_target_with_parent_component_preserves_kv_value() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let artifact = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "parent_component",
        &[("KEY", "value")],
    );
    let secrets_dir = artifact.parent().unwrap();
    fs::create_dir(secrets_dir.join("nested")).unwrap();
    let target = secrets_dir
        .join("nested/..")
        .join(artifact.file_name().unwrap());
    let target = target.to_str().unwrap();

    run_rewrap_with_member_set_review_args(
        &common_opts,
        ALICE_MEMBER_HANDLE,
        &["--rotate-key", "--target", target],
    );

    cmd()
        .arg("get")
        .arg("KEY")
        .arg("--name")
        .arg("parent_component")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env(
            "KAPSARO_SSH_IDENTITY",
            temp_dir.path().join(".ssh/test_ed25519"),
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("value"));
}

#[test]
fn test_rewrap_deduplicates_alternate_spellings_before_rotating() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);
    let artifact = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "deduplicated",
        &[("KEY", "value")],
    );
    let alternate = artifact
        .parent()
        .unwrap()
        .join(".")
        .join(artifact.file_name().unwrap());
    let output = run_duplicate_target_rewrap(&common_opts, &artifact, &alternate);

    assert!(
        output.status.success(),
        "rewrap failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let processed = parsed["summary"]["processed_files"].as_array().unwrap();
    assert_eq!(processed.len(), 1);
    assert!(!processed[0].as_str().unwrap().contains("/./"));
    assert_deduplicated_kv_value(&workspace_dir, &temp_dir);
}

fn run_duplicate_target_rewrap(
    common_opts: &CommonOptions,
    artifact: &Path,
    alternate: &Path,
) -> std::process::Output {
    let mut command = crate::cli::common::kapsaro_std_cmd();
    command
        .arg("rewrap")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--rotate-key")
        .arg("--json")
        .arg("--target")
        .arg(artifact)
        .arg("--target")
        .arg(alternate);
    append_common_command_args(&mut command, common_opts);
    command.output().unwrap()
}

fn assert_deduplicated_kv_value(workspace_dir: &Path, temp_dir: &tempfile::TempDir) {
    cmd()
        .arg("get")
        .arg("KEY")
        .arg("--name")
        .arg("deduplicated")
        .arg("--workspace")
        .arg(workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env(
            "KAPSARO_SSH_IDENTITY",
            temp_dir.path().join(".ssh/test_ed25519"),
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("value"));
}

#[test]
fn test_rewrap_clear_disclosure_history() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let _kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "test_clear_history",
        &[("KEY", "value")],
    );

    fs::remove_file(
        workspace_dir
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE)),
    )
    .unwrap();

    run_rewrap_with_member_set_review(&common_opts, ALICE_MEMBER_HANDLE);

    run_rewrap_with_member_set_review_args(
        &common_opts,
        ALICE_MEMBER_HANDLE,
        &["--clear-disclosure-history"],
    );
}
