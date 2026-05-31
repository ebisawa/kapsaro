// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::app::rewrap::plan::build_rewrap_batch_plan;
use crate::app::rewrap::promotion::build_promotion_review_plan;
use crate::app::rewrap::trust::build_rewrap_trust;
use crate::app::trust::approval::save_known_key_approvals;
use crate::app::trust::RecipientTrustOutcome;
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_write_execution};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::load_trust_store;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::io::workspace::members::load_member_file_from_path;
// (intentionally unused in this file)
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace,
    save_active_public_key_to_workspace_incoming, setup_member_key_context, setup_test_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at, EnvGuard,
};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

fn strict_key_checking_guard() -> EnvGuard {
    let guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    guard
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
