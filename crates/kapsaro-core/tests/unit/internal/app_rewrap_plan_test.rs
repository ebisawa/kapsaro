// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use crate::app::rewrap::plan::build_rewrap_batch_plan;
use crate::app::rewrap::promotion::build_promotion_review_plan;
use crate::app::rewrap::trust::build_rewrap_trust;
use crate::app::rewrap::types::IncomingVerificationCategory;
use crate::app::trust::approval::save_known_key_approvals;
use crate::app::trust::RecipientTrustOutcome;
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_write_execution};
use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::storage::save_key_pair_atomic;
use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::load_trust_store;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::io::workspace::members::load_member_file_from_path;
use crate::model::public_key::GithubAccount;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::time::format_timestamp_rfc3339;
// (intentionally unused in this file)
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace,
    save_active_public_key_to_workspace_incoming, setup_member_key_context, setup_test_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at, EnvGuard,
};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";
const BOB_GITHUB_ID: u64 = 42;
const BOB_GITHUB_LOGIN: &str = "bob-gh";

fn strict_key_checking_guard() -> EnvGuard {
    let guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    guard
}

fn build_verified_ssh_binding(home: &Path) -> SshBindingContext {
    let ssh_key_path = home.join(".ssh").join("test_ed25519");
    let ssh_public_key = fs::read_to_string(home.join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let fingerprint = build_sha256_fingerprint(&ssh_public_key).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_key_path),
    ));

    SshBindingContext {
        public_key: ssh_public_key,
        fingerprint,
        backend,
        determinism: SshDeterminismStatus::Verified,
    }
}

fn save_github_bound_public_key_to_workspace_incoming(
    home: &Path,
    workspace_dir: &Path,
    member_handle: &str,
) {
    let now = time::OffsetDateTime::now_utc();
    let created_at = format_timestamp_rfc3339(now).unwrap();
    let expires_at = format_timestamp_rfc3339(now + time::Duration::days(365)).unwrap();
    let result = generate_key(KeyGenerationOptions {
        member_handle: member_handle.to_string(),
        created_at,
        expires_at,
        debug: false,
        github_account: Some(GithubAccount {
            id: BOB_GITHUB_ID,
            login: BOB_GITHUB_LOGIN.to_string(),
        }),
        ssh_binding: build_verified_ssh_binding(home),
    })
    .unwrap();
    let keystore_root = home.join("keys");
    save_key_pair_atomic(
        &keystore_root,
        member_handle,
        &result.kid,
        &result.private_key,
        &result.public_key,
    )
    .unwrap();
    set_active_kid(member_handle, &result.kid, &keystore_root).unwrap();
    save_active_public_key_to_workspace_incoming(home, workspace_dir, member_handle).unwrap();
}

#[test]
fn test_build_rewrap_batch_plan_rejects_duplicate_kids_across_active_and_incoming() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION kapsaro.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();
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

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let result = build_rewrap_batch_plan(&options, &execution, &[]);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Duplicate kid"));
}

#[test]
fn test_build_rewrap_batch_plan_classifies_github_bound_incoming_as_binding_configured() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION kapsaro.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();
    save_github_bound_public_key_to_workspace_incoming(
        temp_dir.path(),
        &workspace_dir,
        BOB_MEMBER_HANDLE,
    );

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    let report = plan.incoming_report.unwrap();

    assert!(report.failed.is_empty());
    assert!(report.not_configured.is_empty());
    assert_eq!(report.binding_configured.len(), 1);

    let candidate = &report.binding_configured[0];
    assert_eq!(candidate.review.member_handle, BOB_MEMBER_HANDLE);
    assert_eq!(
        candidate.review.category,
        IncomingVerificationCategory::BindingConfigured
    );
    assert!(candidate.review.github_binding_configured);
    assert_eq!(
        candidate.review.message,
        "GitHub binding configured; online verification will run if trust update is required"
    );
}

#[test]
fn test_build_rewrap_trust_treats_accepted_promotions_as_already_reviewed() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION kapsaro.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_paths.clear();
    let review_plan = build_promotion_review_plan(
        plan.incoming_report.as_ref().unwrap(),
        &[],
        &plan.pre_promotion_trust.self_trust,
        true,
    )
    .unwrap();

    let trust_plan = build_rewrap_trust(&plan, &review_plan.prompt_candidates, false).unwrap();

    assert_eq!(trust_plan.recipient_trust, RecipientTrustOutcome::Accepted);
    assert_eq!(trust_plan.accepted_promotion_candidates.len(), 1);
    assert_eq!(
        KnownKeyIdentity::from(&trust_plan.accepted_promotion_candidates[0]).member_handle(),
        BOB_MEMBER_HANDLE
    );
}

#[test]
fn test_build_rewrap_trust_uses_existing_trust_snapshot() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION kapsaro.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_paths.clear();
    plan.pre_promotion_trust.is_interactive = false;

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let result = build_rewrap_trust(&plan, &[], false);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unknown recipient kid"));
}

#[test]
fn test_build_rewrap_trust_includes_recipient_key_expiry_warning() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_HANDLE)
        .unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION kapsaro.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_paths.clear();

    let trust_plan = build_rewrap_trust(&plan, &[], false).unwrap();

    assert!(trust_plan
        .warnings
        .iter()
        .any(|warning| warning.contains("Recipient public key for 'bob@example.com' expires in")));
}

#[test]
fn test_build_rewrap_trust_uses_reviewed_github_login_for_promotion_evidence() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION kapsaro.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_paths.clear();
    let review_plan = build_promotion_review_plan(
        plan.incoming_report.as_ref().unwrap(),
        &[],
        &plan.pre_promotion_trust.self_trust,
        true,
    )
    .unwrap();
    let mut accepted = review_plan.prompt_candidates;
    let candidate = accepted.first_mut().unwrap();
    candidate.review.category = crate::app::rewrap::types::IncomingVerificationCategory::Verified;
    candidate.review.verified_github = Some(VerifiedGithubIdentity::new(
        42,
        "current-login".to_string(),
        "SHA256:fp".to_string(),
        100,
    ));

    let trust_plan = build_rewrap_trust(&plan, &accepted, false).unwrap();
    save_known_key_approvals(
        &options,
        &execution,
        &trust_plan.accepted_promotion_candidates,
    )
    .unwrap();
    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_HANDLE);
    let loaded = load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .unwrap();
    let stored = serde_json::to_value(&loaded.document).unwrap();
    let known_keys = stored["protected"]["known_keys"].as_array().unwrap();
    let bob_entry = known_keys
        .iter()
        .find(|entry| entry["subject_handle"] == serde_json::json!(BOB_MEMBER_HANDLE))
        .unwrap();

    assert_eq!(trust_plan.accepted_promotion_candidates.len(), 1);
    assert_eq!(
        bob_entry["evidence"]["github_account"]["id"],
        serde_json::json!(42)
    );
    assert_eq!(
        bob_entry["evidence"]["github_account"]["login"],
        serde_json::json!("current-login")
    );
}

#[test]
fn test_build_rewrap_trust_replaces_self_rotation_without_persisting_self_known_key() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let active_member_path = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", ALICE_MEMBER_HANDLE));
    let old_active = load_member_file_from_path(&active_member_path).unwrap();
    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &old_key_ctx,
    );
    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        &build_expiring_soon_timestamp(365),
    );
    save_active_public_key_to_workspace_incoming(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
    )
    .unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION kapsaro.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_paths.clear();
    let review_plan = build_promotion_review_plan(
        plan.incoming_report.as_ref().unwrap(),
        &plan.pre_promotion_trust.known_keys,
        &plan.pre_promotion_trust.self_trust,
        true,
    )
    .unwrap();
    let accepted = review_plan.auto_accepted_candidates.clone();

    let trust_plan = build_rewrap_trust(&plan, &accepted, false).unwrap();

    assert_eq!(accepted.len(), 1);
    assert!(review_plan.prompt_candidates.is_empty());
    assert!(trust_plan.accepted_promotion_candidates.is_empty());
    assert_eq!(trust_plan.post_promotion_members.len(), 1);
    assert_eq!(
        trust_plan.post_promotion_members[0]
            .protected
            .subject_handle,
        ALICE_MEMBER_HANDLE
    );
    assert_eq!(
        trust_plan.post_promotion_members[0].protected.kid,
        accepted[0].review.kid
    );
    assert_ne!(
        trust_plan.post_promotion_members[0].protected.kid,
        old_active.protected.kid
    );
}

#[test]
fn test_build_rewrap_batch_plan_uses_only_explicit_targets_when_specified() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let workspace_secret_path = workspace_dir.join("secrets").join("default.kvenc");
    let external_secret_path = temp_dir.path().join("external").join("ca.pem.encrypted");
    fs::create_dir_all(external_secret_path.parent().unwrap()).unwrap();
    fs::write(&workspace_secret_path, "workspace-artifact").unwrap();
    fs::write(&external_secret_path, "external-artifact").unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let plan = build_rewrap_batch_plan(
        &options,
        &execution,
        std::slice::from_ref(&external_secret_path),
    )
    .unwrap();

    assert_eq!(plan.artifact_paths.len(), 1);
    assert!(plan.artifact_paths.contains(&external_secret_path));
    assert!(!plan.artifact_paths.contains(&workspace_secret_path));
}

#[test]
fn test_build_rewrap_batch_plan_accepts_explicit_targets_when_workspace_secrets_is_empty() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let external_secret_path = temp_dir.path().join("external-only.encrypted");
    fs::write(&external_secret_path, "external-artifact").unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let plan = build_rewrap_batch_plan(
        &options,
        &execution,
        std::slice::from_ref(&external_secret_path),
    )
    .unwrap();

    assert_eq!(plan.artifact_paths.len(), 1);
    assert_eq!(plan.artifact_paths[0], external_secret_path);
}
