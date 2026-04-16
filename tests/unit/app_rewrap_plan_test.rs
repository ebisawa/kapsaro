// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::app::rewrap::plan::build_rewrap_batch_plan;
use crate::app::rewrap::promotion::build_promotion_review_plan;
use crate::app::rewrap::trust::build_rewrap_trust;
use crate::app::trust::approval::commit_known_key_approvals;
use crate::app::trust::{RecipientTrustOutcome, SignerTrustOutcome};
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_write_execution};
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::envelope::signature::SigningContext;
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::io::keystore::storage::{list_kids, load_public_key};
use crate::io::trust::paths::trust_store_file_path;
use crate::io::trust::store::load_trust_store;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::io::workspace::members::load_member_file_from_path;
use crate::model::public_key::{BindingClaims, GithubAccount};
use crate::test_utils::{
    build_expiring_soon_timestamp, setup_member_key_context, setup_test_workspace,
    setup_trust_store_for_workspace, stage_active_public_key_to_workspace_incoming,
    sync_active_public_key_to_workspace, update_active_private_key_expires_at, EnvGuard,
};

const ALICE_MEMBER_ID: &str = "alice@example.com";
const BOB_MEMBER_ID: &str = "bob@example.com";

fn strict_key_checking_guard() -> EnvGuard {
    let guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);
    std::env::remove_var("SECRETENV_STRICT_KEY_CHECKING");
    guard
}

fn encrypt_file_for_members(
    home: &std::path::Path,
    signer_member_id: &str,
    signer_kid: &str,
    key_ctx: &crate::feature::context::crypto::CryptoContext,
    recipient_ids: &[&str],
) -> String {
    let keystore_root = home.join("keys");
    let signer_pub = load_public_key(&keystore_root, signer_member_id, signer_kid).unwrap();
    let recipient_members = recipient_ids
        .iter()
        .map(|member_id| {
            let kid = list_kids(&keystore_root, member_id).unwrap().remove(0);
            load_public_key(&keystore_root, member_id, &kid).unwrap()
        })
        .collect::<Vec<_>>();
    let verified_members =
        crate::test_utils::keygen_helpers::make_verified_members(&recipient_members);
    let recipients = recipient_ids
        .iter()
        .map(|member_id| (*member_id).to_string())
        .collect::<Vec<_>>();
    let document = encrypt_file_document(
        b"rewrap-pre-promotion-signer",
        &recipients,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid,
            signer_pub,
            debug: false,
        },
    )
    .unwrap();
    serde_json::to_string_pretty(&document).unwrap()
}

#[test]
fn test_build_rewrap_batch_plan_rejects_duplicate_kids_across_active_and_incoming() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION secretenv.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();
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

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let result = build_rewrap_batch_plan(&options, &execution, &[]);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Duplicate kid"));
}

#[test]
fn test_build_rewrap_trust_treats_accepted_promotions_as_already_reviewed() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION secretenv.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_snapshots.clear();
    let review_plan = build_promotion_review_plan(
        plan.incoming_report.as_ref().unwrap(),
        &[],
        &plan.pre_promotion_trust.self_trust,
        true,
    )
    .unwrap();

    let trust_plan = build_rewrap_trust(&plan, &review_plan.prompt_candidates).unwrap();

    assert_eq!(trust_plan.recipient_trust, RecipientTrustOutcome::Accepted);
    assert_eq!(trust_plan.accepted_promotion_candidates.len(), 1);
    assert_eq!(
        KnownKeyIdentity::from(&trust_plan.accepted_promotion_candidates[0]).member_id(),
        BOB_MEMBER_ID
    );
}

#[test]
fn test_build_rewrap_trust_uses_existing_trust_snapshot() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION secretenv.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_snapshots.clear();
    plan.pre_promotion_trust.is_interactive = false;

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let result = build_rewrap_trust(&plan, &[]);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unknown recipient kid"));
}

#[test]
fn test_build_rewrap_trust_includes_recipient_key_expiry_warning() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_ID, &expires_at);
    sync_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_ID).unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION secretenv.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_snapshots.clear();

    let trust_plan = build_rewrap_trust(&plan, &[]).unwrap();

    assert!(trust_plan
        .warnings
        .iter()
        .any(|warning| warning.contains("Recipient public key for 'bob@example.com' expires in")));
}

#[test]
fn test_build_rewrap_trust_uses_reviewed_github_login_for_promotion_evidence() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION secretenv.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_snapshots.clear();
    let review_plan = build_promotion_review_plan(
        plan.incoming_report.as_ref().unwrap(),
        &[],
        &plan.pre_promotion_trust.self_trust,
        true,
    )
    .unwrap();
    let mut accepted = review_plan.prompt_candidates;
    let candidate = accepted.first_mut().unwrap();
    candidate.public_key.protected.binding_claims = Some(BindingClaims {
        github_account: Some(GithubAccount {
            id: 42,
            login: "stale-login".to_string(),
        }),
    });
    candidate.review.category = crate::app::rewrap::types::IncomingVerificationCategory::Verified;
    candidate.review.verified_github = Some(VerifiedGithubIdentity::new(
        42,
        "current-login".to_string(),
        "SHA256:fp".to_string(),
        100,
    ));

    let trust_plan = build_rewrap_trust(&plan, &accepted).unwrap();
    commit_known_key_approvals(
        &options,
        &execution,
        &trust_plan.accepted_promotion_candidates,
    )
    .unwrap();
    let trust_path = trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .unwrap();
    let stored = serde_json::to_value(&loaded.document).unwrap();
    let known_keys = stored["protected"]["known_keys"].as_array().unwrap();
    let bob_entry = known_keys
        .iter()
        .find(|entry| entry["member_id"] == serde_json::json!(BOB_MEMBER_ID))
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
fn test_build_rewrap_trust_uses_pre_promotion_snapshot_for_signer_review() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let bob_key_ctx = setup_member_key_context(&temp_dir, BOB_MEMBER_ID, None);
    let encrypted = encrypt_file_for_members(
        temp_dir.path(),
        BOB_MEMBER_ID,
        &bob_key_ctx.kid,
        &bob_key_ctx,
        &[ALICE_MEMBER_ID, BOB_MEMBER_ID],
    );
    let secret_path = workspace_dir
        .join("secrets")
        .join("signed-by-incoming.json");
    fs::write(&secret_path, encrypted).unwrap();

    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();

    let alice_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_ID,
        &alice_key_ctx,
    );

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.pre_promotion_trust.is_interactive = true;
    let review_plan = build_promotion_review_plan(
        plan.incoming_report.as_ref().unwrap(),
        &[],
        &plan.pre_promotion_trust.self_trust,
        true,
    )
    .unwrap();

    let trust_plan = build_rewrap_trust(&plan, &review_plan.prompt_candidates).unwrap();

    assert_eq!(trust_plan.signer_requirements.len(), 1);
    match &trust_plan.signer_requirements[0].outcome {
        SignerTrustOutcome::NeedsNonMemberAcceptance { candidate, .. } => {
            assert_eq!(candidate.member_id, BOB_MEMBER_ID);
        }
        other => panic!("unexpected signer outcome: {:?}", other),
    }
}

#[test]
fn test_build_rewrap_batch_plan_freezes_incoming_candidate_snapshot() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION secretenv.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    let snapshotted = plan
        .incoming_report
        .as_ref()
        .unwrap()
        .not_configured
        .first()
        .unwrap()
        .source_content
        .clone();

    let mut tampered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bob_incoming).unwrap()).unwrap();
    tampered["protected"]["created_at"] =
        serde_json::Value::String("2026-12-31T23:59:59Z".to_string());
    fs::write(
        &bob_incoming,
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .unwrap();

    assert_ne!(fs::read_to_string(&bob_incoming).unwrap(), snapshotted);
}

#[test]
fn test_build_rewrap_batch_plan_freezes_input_artifact_snapshot() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let secret_path = workspace_dir.join("secrets").join("default.kvenc");
    fs::write(&secret_path, "original-artifact").unwrap();
    let original = fs::read_to_string(&secret_path).unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    let snapshotted = plan.artifact_snapshots.first().unwrap().content.clone();

    fs::write(&secret_path, "tampered-artifact").unwrap();

    assert_eq!(snapshotted, original);
    assert_ne!(fs::read_to_string(&secret_path).unwrap(), snapshotted);
}

#[test]
fn test_build_rewrap_trust_replaces_self_rotation_without_persisting_self_known_key() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let active_member_path = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", ALICE_MEMBER_ID));
    let old_active = load_member_file_from_path(&active_member_path).unwrap();
    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_ID,
        &old_key_ctx,
    );
    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_ID,
        &build_expiring_soon_timestamp(365),
    );
    stage_active_public_key_to_workspace_incoming(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID)
        .unwrap();
    fs::write(
        workspace_dir.join("secrets").join("default.kvenc"),
        "VERSION secretenv.kv-enc@3\nWRAP eyJ3cmFwIjpbXX0\n",
    )
    .unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let mut plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    plan.artifact_snapshots.clear();
    let review_plan = build_promotion_review_plan(
        plan.incoming_report.as_ref().unwrap(),
        &plan.pre_promotion_trust.known_keys,
        &plan.pre_promotion_trust.self_trust,
        true,
    )
    .unwrap();
    let accepted = review_plan.auto_accepted_candidates.clone();

    let trust_plan = build_rewrap_trust(&plan, &accepted).unwrap();

    assert_eq!(accepted.len(), 1);
    assert!(review_plan.prompt_candidates.is_empty());
    assert!(trust_plan.accepted_promotion_candidates.is_empty());
    assert_eq!(trust_plan.post_promotion_members.len(), 1);
    assert_eq!(
        trust_plan.post_promotion_members[0].protected.member_id,
        ALICE_MEMBER_ID
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
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let workspace_secret_path = workspace_dir.join("secrets").join("default.kvenc");
    let external_secret_path = temp_dir.path().join("external").join("ca.pem.encrypted");
    fs::create_dir_all(external_secret_path.parent().unwrap()).unwrap();
    fs::write(&workspace_secret_path, "workspace-artifact").unwrap();
    fs::write(&external_secret_path, "external-artifact").unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let plan = build_rewrap_batch_plan(
        &options,
        &execution,
        std::slice::from_ref(&external_secret_path),
    )
    .unwrap();

    let snapshotted_paths = plan
        .artifact_snapshots
        .iter()
        .map(|snapshot| snapshot.file_path.clone())
        .collect::<Vec<_>>();
    assert_eq!(snapshotted_paths.len(), 1);
    assert!(snapshotted_paths.contains(&external_secret_path));
    assert!(!snapshotted_paths.contains(&workspace_secret_path));
}

#[test]
fn test_build_rewrap_batch_plan_uses_only_explicit_workspace_target_when_specified() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let target_secret_path = workspace_dir.join("secrets").join("default.kvenc");
    let other_secret_path = workspace_dir.join("secrets").join("other.kvenc");
    fs::write(&target_secret_path, "target-artifact").unwrap();
    fs::write(&other_secret_path, "other-artifact").unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let plan = build_rewrap_batch_plan(
        &options,
        &execution,
        std::slice::from_ref(&target_secret_path),
    )
    .unwrap();

    assert_eq!(plan.artifact_snapshots.len(), 1);
    assert_eq!(plan.artifact_snapshots[0].file_path, target_secret_path);
}

#[test]
fn test_build_rewrap_batch_plan_accepts_explicit_targets_when_workspace_secrets_is_empty() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let external_secret_path = temp_dir.path().join("external-only.encrypted");
    fs::write(&external_secret_path, "external-artifact").unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let plan = build_rewrap_batch_plan(
        &options,
        &execution,
        std::slice::from_ref(&external_secret_path),
    )
    .unwrap();

    assert_eq!(plan.artifact_snapshots.len(), 1);
    assert_eq!(plan.artifact_snapshots[0].file_path, external_secret_path);
}
