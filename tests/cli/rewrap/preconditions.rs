// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at, EnvGuard,
};
use console::strip_ansi_codes;
use kapsaro_test_support::crypto_context::setup_member_key_context;

#[cfg(unix)]
use kapsaro_core::test_support::storage::trust::paths::get_trust_store_file_path;

#[cfg(unix)]
struct PromotionSideEffectFixture {
    _temp_dir: tempfile::TempDir,
    workspace_dir: PathBuf,
    common_opts: CommonOptions,
    artifact_path: PathBuf,
    artifact_before: Vec<u8>,
    active_path: PathBuf,
    incoming_path: PathBuf,
    incoming_before: Vec<u8>,
    trust_path: PathBuf,
    trust_before: Vec<u8>,
}

#[cfg(unix)]
fn setup_promotion_side_effect_fixture() -> PromotionSideEffectFixture {
    use crate::test_utils::member_handle;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let common_opts = build_preflight_common_options(&temp_dir, &workspace_dir);
    let artifact_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "preflight",
        &[("KEY", "value")],
    );
    let (active_path, incoming_path) = setup_bob_incoming(&workspace_dir);
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));

    PromotionSideEffectFixture {
        artifact_before: fs::read(&artifact_path).unwrap(),
        incoming_before: fs::read(&incoming_path).unwrap(),
        trust_before: fs::read(&trust_path).unwrap(),
        _temp_dir: temp_dir,
        workspace_dir,
        common_opts,
        artifact_path,
        active_path,
        incoming_path,
        trust_path,
    }
}

#[cfg(unix)]
fn build_preflight_common_options(
    temp_dir: &tempfile::TempDir,
    workspace_dir: &Path,
) -> CommonOptions {
    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.to_path_buf());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, temp_dir);
    common_opts
}

#[cfg(unix)]
fn setup_bob_incoming(workspace_dir: &Path) -> (PathBuf, PathBuf) {
    let active_path = workspace_dir
        .join("members/active")
        .join(format!("{BOB_MEMBER_HANDLE}.json"));
    let incoming_path = workspace_dir
        .join("members/incoming")
        .join(format!("{BOB_MEMBER_HANDLE}.json"));
    fs::rename(&active_path, &incoming_path).unwrap();
    (active_path, incoming_path)
}

#[cfg(unix)]
fn assert_promotion_side_effects_absent(fixture: &PromotionSideEffectFixture) {
    assert!(!fixture.active_path.exists());
    assert_eq!(
        fs::read(&fixture.incoming_path).unwrap(),
        fixture.incoming_before
    );
    assert_eq!(fs::read(&fixture.trust_path).unwrap(), fixture.trust_before);
    assert_eq!(
        fs::read(&fixture.artifact_path).unwrap(),
        fixture.artifact_before
    );
}

#[cfg(unix)]
fn assert_no_promotion_prompt(output: &std::process::Output) {
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !rendered.contains("Accept?"),
        "unexpected prompt: {rendered}"
    );
    assert!(
        !rendered.contains("Secret sharing review"),
        "unexpected promotion review: {rendered}"
    );
}

#[cfg(unix)]
#[test]
fn test_rewrap_strict_key_checking_no_before_side_effects_error() {
    let fixture = setup_promotion_side_effect_fixture();
    let output = build_rewrap_command(&fixture.common_opts, ALICE_MEMBER_HANDLE, &[])
        .env("KAPSARO_STRICT_KEY_CHECKING", "no")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("KAPSARO_STRICT_KEY_CHECKING=no is not allowed for rewrap"));
    assert_no_promotion_prompt(&output);
    assert_promotion_side_effects_absent(&fixture);
}

#[test]
fn test_rewrap_strict_key_checking_no_before_resolving_paths_error() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("missing-home");
    let workspace = root.path().join("missing-workspace");
    let mut common_opts = default_common_options();
    common_opts.home = Some(home.clone());
    common_opts.workspace = Some(workspace.clone());
    let output = build_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[])
        .env("KAPSARO_STRICT_KEY_CHECKING", "no")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("KAPSARO_STRICT_KEY_CHECKING=no is not allowed for rewrap"));
    assert!(!home.exists());
    assert!(!workspace.exists());
}

#[cfg(unix)]
#[test]
fn test_rewrap_missing_target_before_promotion_error() {
    let fixture = setup_promotion_side_effect_fixture();
    let missing = fixture.workspace_dir.join("missing.json");

    let output = run_rewrap_command(
        &fixture.common_opts,
        ALICE_MEMBER_HANDLE,
        &["--target", missing.to_str().unwrap()],
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no such file"));
    assert_no_promotion_prompt(&output);
    assert_promotion_side_effects_absent(&fixture);
}

#[test]
fn test_rewrap_requires_workspace() {
    let (temp_dir, _workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = None;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let invalid_workspace = temp_dir.path().join("workspace-does-not-exist");
    let _guard = EnvGuard::new(&["KAPSARO_WORKSPACE"]);
    std::env::set_var("KAPSARO_WORKSPACE", &invalid_workspace);
    let output = run_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[]);

    assert!(!output.status.success(), "Should fail without workspace");
}

#[cfg(unix)]
#[test]
fn test_rewrap_with_no_files_fails_gracefully() {
    use crate::test_utils::member_handle;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let (active_path, incoming_path) = setup_bob_incoming(&workspace_dir);
    let common_opts = build_preflight_common_options(&temp_dir, &workspace_dir);
    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let trust_before = fs::read(&trust_path).unwrap();

    let output = run_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[]);
    assert!(
        !output.status.success(),
        "Should fail with no files in secrets/"
    );

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("No encrypted files"),
        "Error should mention no files found: {}",
        err_msg
    );
    assert_no_promotion_prompt(&output);
    assert!(!active_path.exists());
    assert!(incoming_path.exists());
    assert_eq!(fs::read(trust_path).unwrap(), trust_before);
}

#[test]
fn test_rewrap_nonexistent_workspace_fails() {
    let (_ssh_temp, ssh_priv, _ssh_pub, _pub_content) = generate_temp_ssh_keypair();
    let home_dir = tempfile::TempDir::new().unwrap();

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg("/tmp/nonexistent_workspace_kapsaro_test")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_rewrap_quiet_keeps_failed_file_details_on_stderr() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) =
        setup_workspace_with_kv_entries(&[("BROKEN_KEY", "broken_value")]);
    let kv_path = workspace_dir.path().join("secrets").join("default.kvenc");
    tamper_kv_signature(&kv_path);

    let assert = cmd()
        .arg("rewrap")
        .arg("--quiet")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("\u{1b}[31mError processing "),
        "expected colored failed file detail in stderr, got: {stderr}"
    );
    assert!(
        strip_ansi_codes(&stderr).contains("Signature verification failed"),
        "expected failure detail after stripping ANSI, got: {stderr}"
    );
    assert!(
        strip_ansi_codes(&stderr).contains("Failed to rewrap 1 file(s). See errors above."),
        "expected top-level rewrap failure after stripping ANSI, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_rewrap_warns_about_insecure_trust_store_permissions() {
    use crate::test_utils::member_handle;
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
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

    save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "warn_rewrap",
        &[("KEY", "value")],
    );

    let trust_path =
        get_trust_store_file_path(temp_dir.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let output = run_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rewrap must complete despite an insecure trust store: {stderr}"
    );
    assert!(
        stderr.contains("Insecure permissions 0644"),
        "missing warning: {stderr}"
    );
    assert!(
        stderr.contains("(expected 0600)") && stderr.contains("chmod 0600"),
        "warning must name the required permissions and the fix: {stderr}"
    );
}

#[test]
fn test_rewrap_surfaces_recipient_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
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

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    save_kv_file(
        &workspace_dir,
        common_opts,
        ALICE_MEMBER_HANDLE,
        "recipient_expiry",
        &[("KEY", "value")],
    );

    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");
    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: Recipient public key for 'bob@example.com' expires in",
        ));
}
