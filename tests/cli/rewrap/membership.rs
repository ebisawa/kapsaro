// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::cli::common::{kapsaro_bin, run_command_with_pty};
use crate::test_utils::setup_trust_store_for_workspace;
use kapsaro_core::cli_api::test_support::domain::ssh::SshDeterminismStatus;
use kapsaro_core::cli_api::test_support::operations::key::public_key_document::{
    build_attestation, build_public_key, PublicKeyDocumentParams,
};
use kapsaro_core::cli_api::test_support::operations::key::ssh_binding::SshBindingContext;
use kapsaro_core::cli_api::test_support::storage::keystore::active::set_active_kid;
use kapsaro_core::cli_api::test_support::storage::keystore::storage::list_kids;
use kapsaro_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::fingerprint::build_sha256_fingerprint;
use kapsaro_core::cli_api::test_support::storage::trust::paths::get_trust_store_file_path;
use kapsaro_core::cli_api::test_support::storage::workspace::members::load_member_file_from_path;
use kapsaro_core::cli_api::test_support::wire::public_key::AttestationBodyInput;
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::fixture::setup_test_workspace_from_fixtures;
#[cfg(unix)]
use std::process::Command as StdCommand;

fn test_ssh_binding(temp_dir: &tempfile::TempDir) -> SshBindingContext {
    let ssh_private_key = temp_dir.path().join(".ssh").join("test_ed25519");
    let public_key = fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    SshBindingContext {
        fingerprint: build_sha256_fingerprint(&public_key).unwrap(),
        public_key,
        backend: Box::new(
            kapsaro_test_support::ed25519_backend::Ed25519DirectBackend::new(&ssh_private_key)
                .unwrap(),
        ) as Box<dyn SignatureBackend>,
        determinism: SshDeterminismStatus::Verified,
    }
}

fn rewrite_member_with_foreign_identity(
    temp_dir: &tempfile::TempDir,
    source_member_file: &std::path::Path,
    target_member_file: &std::path::Path,
    target_member_handle: &str,
    signer_handle: &str,
) {
    let key_ctx = setup_member_key_context(temp_dir, signer_handle, None);
    let source = load_member_file_from_path(source_member_file).unwrap();
    let created_at = source.protected.created_at.clone().unwrap();
    let expires_at = source.protected.expires_at.clone();
    let keys = source.protected.keys;
    let binding_claims = None;
    let attestation = build_attestation(
        &test_ssh_binding(temp_dir),
        &AttestationBodyInput {
            subject_handle: target_member_handle,
            keys: &keys,
            binding_claims: binding_claims.as_ref(),
            created_at: Some(&created_at),
            expires_at: &expires_at,
        },
    )
    .unwrap();
    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_handle: target_member_handle,
        keys,
        binding_claims,
        attestation,
        created_at: &created_at,
        expires_at: &expires_at,
        sig_sk: key_ctx.signing_key(),
        debug: false,
    })
    .unwrap();
    fs::write(
        target_member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn test_rewrap_accept_prompt_accepts_carriage_return_in_pty() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);
    let alice_kid = list_kids(&temp_dir.path().join("keys"), ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(
        ALICE_MEMBER_HANDLE,
        &alice_kid,
        &temp_dir.path().join("keys"),
    )
    .unwrap();
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    fs::rename(&bob_active, &bob_incoming).unwrap();

    let _kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "pty_accept",
        &[("KEY", "value")],
    );

    let mut command = StdCommand::new(kapsaro_bin());
    command
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env(
            "KAPSARO_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        )
        .env("KAPSARO_SSH_SIGNING_METHOD", "ssh-keygen")
        .env_remove("CI");

    let result = run_command_with_pty(&mut command, "Trust this member set", b"y\r");

    assert!(
        result.status.success(),
        "interactive rewrap should succeed after carriage return input\n{}",
        result.output
    );
    assert!(
        result.output.contains("Secret sharing review")
            && result.output.contains("Trust this member set"),
        "interactive output should include member set prompt\n{}",
        result.output
    );
    assert!(
        !result.output.contains("^M"),
        "interactive output should not echo literal carriage-return markers\n{}",
        result.output
    );
}

#[test]
fn test_rewrap_rejects_self_incoming_when_local_identity_mismatches() {
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
        "self_mismatch",
        &[("KEY", "value")],
    );

    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let alice_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", ALICE_MEMBER_HANDLE));
    rewrite_member_with_foreign_identity(
        &temp_dir,
        &bob_active,
        &alice_incoming,
        ALICE_MEMBER_HANDLE,
        BOB_MEMBER_HANDLE,
    );

    let output = run_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did not match local keystore identity"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn test_rewrap_requires_recipient_trust_approval() {
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
        "trust_gate",
        &[("KEY", "value")],
    );

    fs::remove_file(get_trust_store_file_path(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
    ))
    .unwrap();

    let output = run_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown recipient kid"));
}

#[test]
fn test_rewrap_rejects_duplicate_kid_workspace_before_processing() {
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
        common_opts,
        ALICE_MEMBER_HANDLE,
        "duplicate_workspace",
        &[("KEY", "value")],
    );
    fs::copy(
        workspace_dir
            .join("members")
            .join("active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE)),
        workspace_dir
            .join("members")
            .join("incoming")
            .join(format!("{}.json", BOB_MEMBER_HANDLE)),
    )
    .unwrap();

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env(
            "KAPSARO_SSH_IDENTITY",
            temp_dir.path().join(".ssh").join("test_ed25519"),
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("Duplicate kid"));
}
