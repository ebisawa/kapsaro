// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::rewrap::execution::{
    apply_rewrap_promotions, execute_confirmed_rewrap_batch, execute_rewrap_batch,
};
use crate::app::rewrap::plan::build_rewrap_batch_plan;
use crate::app::rewrap::types::{
    IncomingPromotionCandidate, RewrapArtifactSnapshot, RewrapBatchPlan, RewrapBatchRequest,
    VerifiedPostPromotionRecipients,
};
use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{current_self_sig_x, CommandTrustSnapshot, RewrapInputPolicy};
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_write_execution};
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::envelope::signature::SigningContext;
use crate::feature::trust::verification::verify_trust_store;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::format::content::FileEncContent;
use crate::io::keystore::storage::{list_kids, load_public_key};
use crate::io::trust::paths::trust_store_file_path;
use crate::io::trust::store::load_trust_store;
use crate::io::workspace::members::{
    incoming_member_file_path, load_active_member_files, load_incoming_member_files,
    load_member_file_from_path,
};
use crate::test_utils::{
    build_expiring_soon_timestamp, setup_member_key_context, setup_test_workspace,
    stage_active_public_key_to_workspace_incoming, update_active_private_key_expires_at, EnvGuard,
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
    signer_kid: &str,
    key_ctx: &crate::feature::context::crypto::CryptoContext,
    recipient_ids: &[&str],
) -> String {
    let keystore_root = home.join("keys");
    let signer_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, signer_kid).unwrap();
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
        b"snapshot-test-secret",
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

fn find_incoming_candidate(
    workspace: &std::path::Path,
    member_id: &str,
) -> IncomingPromotionCandidate {
    let source_path = incoming_member_file_path(workspace, member_id);
    let public_key = load_member_file_from_path(&source_path).unwrap();
    let source_content = fs::read_to_string(&source_path).unwrap();
    IncomingPromotionCandidate {
        review: crate::app::rewrap::types::IncomingVerificationItem {
            member_id: member_id.to_string(),
            kid: public_key.protected.kid.clone(),
            category: crate::app::rewrap::types::IncomingVerificationCategory::NotConfigured,
            message: "snapshot".to_string(),
            fingerprint: None,
            verified_github: None,
            github_binding_configured: false,
            attestor_pub: Some(public_key.protected.identity.attestation.pub_.clone()),
        },
        source_path,
        source_content,
        public_key,
    }
}

fn build_empty_plan(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
    workspace_dir: &std::path::Path,
) -> RewrapBatchPlan {
    let pre_promotion_trust = CommandTrustSnapshot::<RewrapInputPolicy>::load(
        options,
        workspace_dir,
        &execution.member_id,
        Some(current_self_sig_x(&execution.key_ctx.signing_key)),
        options.verbose,
    )
    .unwrap()
    .trust_context()
    .clone();
    RewrapBatchPlan {
        workspace_root: workspace_dir.to_path_buf(),
        pre_promotion_trust,
        incoming_report: None,
        artifact_snapshots: Vec::new(),
    }
}

fn build_verified_post_promotion_recipients(
    members: Vec<crate::model::public_key::PublicKey>,
) -> VerifiedPostPromotionRecipients {
    let verified = verify_recipient_public_keys(&members, false).unwrap();
    VerifiedPostPromotionRecipients::new(verified)
}

#[test]
fn test_execute_rewrap_batch_does_not_promote_members() {
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

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let plan = build_empty_plan(&options, &execution, &workspace_dir);
    let request = RewrapBatchRequest {
        options,
        rotate_key: false,
        clear_disclosure_history: false,
        accepted_promotions: vec![find_incoming_candidate(&workspace_dir, BOB_MEMBER_ID)],
    };

    let outcome = execute_rewrap_batch(
        &request,
        &plan,
        execution,
        &build_verified_post_promotion_recipients(
            load_active_member_files(&workspace_dir).unwrap(),
        ),
    )
    .unwrap();

    assert!(outcome.processed_files.is_empty());
    assert!(outcome.failed_files.is_empty());
    assert!(outcome.promoted_member_ids.is_empty());
    assert_eq!(load_active_member_files(&workspace_dir).unwrap().len(), 1);
    assert_eq!(load_incoming_member_files(&workspace_dir).unwrap().len(), 1);
}

#[test]
fn test_apply_rewrap_promotions_moves_accepted_members_to_active() {
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

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    assert!(!key_ctx.kid.is_empty());

    let bob = find_incoming_candidate(&workspace_dir, BOB_MEMBER_ID);

    apply_rewrap_promotions(&workspace_dir, &[bob]).unwrap();

    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let incoming_members = load_incoming_member_files(&workspace_dir).unwrap();
    assert!(active_members
        .iter()
        .any(|member| member.protected.member_id == BOB_MEMBER_ID));
    assert!(incoming_members.is_empty());
}

#[test]
fn test_apply_rewrap_promotions_replaces_existing_active_member_on_rotation() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let active_path = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", ALICE_MEMBER_ID));
    let old_active = load_member_file_from_path(&active_path).unwrap();
    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_ID,
        &build_expiring_soon_timestamp(365),
    );
    stage_active_public_key_to_workspace_incoming(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID)
        .unwrap();

    let alice = find_incoming_candidate(&workspace_dir, ALICE_MEMBER_ID);

    apply_rewrap_promotions(&workspace_dir, &[alice]).unwrap();

    let active_members = load_active_member_files(&workspace_dir).unwrap();
    let incoming_members = load_incoming_member_files(&workspace_dir).unwrap();
    assert_eq!(active_members.len(), 1);
    assert_eq!(active_members[0].protected.member_id, ALICE_MEMBER_ID);
    assert_ne!(active_members[0].protected.kid, old_active.protected.kid);
    assert!(incoming_members.is_empty());
}

#[test]
fn test_execute_confirmed_rewrap_batch_persists_approvals_before_file_failures() {
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
    let invalid_file = workspace_dir.join("secrets").join("broken.json");
    fs::write(&invalid_file, "not encrypted").unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let bob_candidate = find_incoming_candidate(&workspace_dir, BOB_MEMBER_ID);
    let incoming_members = load_incoming_member_files(&workspace_dir).unwrap();
    let bob = incoming_members
        .iter()
        .find(|member| member.protected.member_id == BOB_MEMBER_ID)
        .unwrap();
    let plan = RewrapBatchPlan {
        workspace_root: workspace_dir.clone(),
        pre_promotion_trust: CommandTrustSnapshot::<RewrapInputPolicy>::load(
            &options,
            &workspace_dir,
            &execution.member_id,
            Some(current_self_sig_x(&execution.key_ctx.signing_key)),
            options.verbose,
        )
        .unwrap()
        .trust_context()
        .clone(),
        incoming_report: None,
        artifact_snapshots: vec![RewrapArtifactSnapshot {
            file_path: invalid_file.clone(),
            content: fs::read_to_string(&invalid_file).unwrap(),
        }],
    };
    let request = RewrapBatchRequest {
        options,
        rotate_key: false,
        clear_disclosure_history: false,
        accepted_promotions: vec![bob_candidate],
    };
    let approvals = vec![ApprovedKnownKey::from_review(
        &bob.protected.member_id,
        &bob.protected.kid,
        Some(bob.protected.identity.attestation.pub_.clone()),
        None,
    )];
    let mut expected_post_promotion_members = load_active_member_files(&workspace_dir).unwrap();
    expected_post_promotion_members.push(bob.clone());

    let outcome = execute_confirmed_rewrap_batch(
        &request,
        &plan,
        &expected_post_promotion_members,
        execution,
        &approvals,
    )
    .unwrap();

    assert!(outcome.processed_files.is_empty());
    assert_eq!(outcome.failed_files.len(), 1);
    assert_eq!(outcome.promoted_member_ids, vec![BOB_MEMBER_ID.to_string()]);
    assert!(load_active_member_files(&workspace_dir)
        .unwrap()
        .iter()
        .any(|member| member.protected.member_id == BOB_MEMBER_ID));

    let trust_path = trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    let loaded = load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .unwrap();
    let verified = verify_trust_store(&loaded.document, &temp_dir.path().join("keys")).unwrap();
    assert!(verified
        .document()
        .protected
        .known_keys
        .iter()
        .any(|entry| entry.member_id == BOB_MEMBER_ID && entry.kid == bob.protected.kid));
}

#[test]
fn test_execute_confirmed_rewrap_batch_rejects_expired_signing_key_before_trust_update() {
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

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let mut execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    execution.key_ctx.expires_at = "2020-01-01T00:00:00Z".to_string();
    let bob_candidate = find_incoming_candidate(&workspace_dir, BOB_MEMBER_ID);
    let incoming_members = load_incoming_member_files(&workspace_dir).unwrap();
    let bob = incoming_members
        .iter()
        .find(|member| member.protected.member_id == BOB_MEMBER_ID)
        .unwrap();
    let plan = build_empty_plan(&options, &execution, &workspace_dir);
    let request = RewrapBatchRequest {
        options,
        rotate_key: false,
        clear_disclosure_history: false,
        accepted_promotions: vec![bob_candidate],
    };
    let approvals = vec![ApprovedKnownKey::from_review(
        &bob.protected.member_id,
        &bob.protected.kid,
        Some(bob.protected.identity.attestation.pub_.clone()),
        None,
    )];
    let mut expected_post_promotion_members = load_active_member_files(&workspace_dir).unwrap();
    expected_post_promotion_members.push(bob.clone());

    let result = execute_confirmed_rewrap_batch(
        &request,
        &plan,
        &expected_post_promotion_members,
        execution,
        &approvals,
    );

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.to_string().contains("expired"));
    assert!(load_active_member_files(&workspace_dir)
        .unwrap()
        .iter()
        .any(|member| member.protected.member_id == BOB_MEMBER_ID));
    let trust_path = trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    assert!(load_trust_store(&trust_path, temp_dir.path())
        .unwrap()
        .is_none());
}

#[test]
fn test_apply_rewrap_promotions_rejects_incoming_file_mismatch_after_review() {
    let _guard = strict_key_checking_guard();
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();

    let bob_candidate = find_incoming_candidate(&workspace_dir, BOB_MEMBER_ID);
    let reviewed_kid = bob_candidate.review.kid.clone();
    let reviewed_source = bob_candidate.source_content.clone();

    let mut tampered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bob_incoming).unwrap()).unwrap();
    tampered["protected"]["created_at"] =
        serde_json::Value::String("2026-12-31T23:59:59Z".to_string());
    fs::write(
        &bob_incoming,
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .unwrap();

    let result = apply_rewrap_promotions(&workspace_dir, &[bob_candidate]);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("changed since review"));
    assert!(!load_active_member_files(&workspace_dir)
        .unwrap()
        .iter()
        .any(|member| member.protected.member_id == BOB_MEMBER_ID));
    assert!(bob_incoming.exists());
    let current_incoming = fs::read_to_string(&bob_incoming).unwrap();
    assert_ne!(current_incoming, reviewed_source);
    assert_eq!(
        load_member_file_from_path(&bob_incoming)
            .unwrap()
            .protected
            .kid,
        reviewed_kid
    );
}

#[test]
fn test_execute_rewrap_batch_uses_fixed_post_promotion_members() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let alice_kid = execution.key_ctx.kid.clone();
    let encrypted = encrypt_file_for_members(
        temp_dir.path(),
        &alice_kid,
        &execution.key_ctx,
        &[ALICE_MEMBER_ID, BOB_MEMBER_ID],
    );
    let secret_path = workspace_dir.join("secrets").join("snapshot-file.json");
    fs::write(&secret_path, encrypted).unwrap();
    let plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    let request = RewrapBatchRequest {
        options,
        rotate_key: false,
        clear_disclosure_history: false,
        accepted_promotions: Vec::new(),
    };
    let fixed_members = build_verified_post_promotion_recipients(
        load_active_member_files(&workspace_dir)
            .unwrap()
            .into_iter()
            .filter(|member| member.protected.member_id == ALICE_MEMBER_ID)
            .collect::<Vec<_>>(),
    );

    let outcome = execute_rewrap_batch(&request, &plan, execution, &fixed_members).unwrap();

    assert_eq!(outcome.failed_files.len(), 0);
    let rewritten = fs::read_to_string(&secret_path).unwrap();
    let document: crate::model::file_enc::FileEncDocument =
        serde_json::from_str(FileEncContent::new_unchecked(rewritten).as_str()).unwrap();
    let recipients = document
        .protected
        .wrap
        .iter()
        .map(|wrap| wrap.rid.clone())
        .collect::<Vec<_>>();
    assert_eq!(recipients, vec![ALICE_MEMBER_ID.to_string()]);
}

#[test]
fn test_execute_rewrap_batch_rejects_artifact_mismatch_after_review() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let alice_kid = execution.key_ctx.kid.clone();
    let encrypted = encrypt_file_for_members(
        temp_dir.path(),
        &alice_kid,
        &execution.key_ctx,
        &[ALICE_MEMBER_ID, BOB_MEMBER_ID],
    );
    let secret_path = workspace_dir.join("secrets").join("stale-file.json");
    fs::write(&secret_path, &encrypted).unwrap();

    let plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    let tampered = encrypt_file_for_members(
        temp_dir.path(),
        &alice_kid,
        &execution.key_ctx,
        &[ALICE_MEMBER_ID],
    );
    fs::write(&secret_path, &tampered).unwrap();

    let request = RewrapBatchRequest {
        options,
        rotate_key: false,
        clear_disclosure_history: false,
        accepted_promotions: Vec::new(),
    };
    let fixed_members =
        build_verified_post_promotion_recipients(load_active_member_files(&workspace_dir).unwrap());

    let outcome = execute_rewrap_batch(&request, &plan, execution, &fixed_members).unwrap();

    assert!(outcome.processed_files.is_empty());
    assert_eq!(outcome.failed_files.len(), 1);
    assert!(outcome.failed_files[0]
        .error_message
        .contains("changed since review"));
    assert_eq!(fs::read_to_string(&secret_path).unwrap(), tampered);
}

#[test]
fn test_execute_confirmed_rewrap_batch_rejects_actual_post_promotion_snapshot_mismatch() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) =
        setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID, "carol"]);
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_ID));
    fs::rename(&bob_active, &bob_incoming).unwrap();

    let carol_active = workspace_dir
        .join("members")
        .join("active")
        .join("carol.json");
    let carol_backup = fs::read_to_string(&carol_active).unwrap();
    fs::remove_file(&carol_active).unwrap();

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let plan = build_empty_plan(&options, &execution, &workspace_dir);
    let request = RewrapBatchRequest {
        options,
        rotate_key: false,
        clear_disclosure_history: false,
        accepted_promotions: vec![find_incoming_candidate(&workspace_dir, BOB_MEMBER_ID)],
    };
    let expected_post_promotion_members = vec![
        load_active_member_files(&workspace_dir)
            .unwrap()
            .into_iter()
            .find(|member| member.protected.member_id == ALICE_MEMBER_ID)
            .unwrap(),
        load_member_file_from_path(&bob_incoming).unwrap(),
    ];

    fs::write(&carol_active, carol_backup).unwrap();

    let result = execute_confirmed_rewrap_batch(
        &request,
        &plan,
        &expected_post_promotion_members,
        execution,
        &[],
    );

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err
        .to_string()
        .contains("post-promotion active members changed"));
}

#[test]
fn test_execute_confirmed_rewrap_batch_rejects_invalid_post_promotion_recipient_keys() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_ID);
    let encrypted = encrypt_file_for_members(
        temp_dir.path(),
        &execution.key_ctx.kid,
        &execution.key_ctx,
        &[ALICE_MEMBER_ID, BOB_MEMBER_ID],
    );
    let secret_path = workspace_dir.join("secrets").join("invalid-recipient.json");
    fs::write(&secret_path, encrypted).unwrap();
    let plan = build_rewrap_batch_plan(&options, &execution, &[]).unwrap();
    let request = RewrapBatchRequest {
        options,
        rotate_key: false,
        clear_disclosure_history: false,
        accepted_promotions: Vec::new(),
    };

    let bob_file = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_ID));
    let mut tampered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bob_file).unwrap()).unwrap();
    tampered["protected"]["expires_at"] =
        serde_json::Value::String("2020-01-01T00:00:00Z".to_string());
    fs::write(&bob_file, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
    let expected_post_promotion_members = load_active_member_files(&workspace_dir).unwrap();

    let result = execute_confirmed_rewrap_batch(
        &request,
        &plan,
        &expected_post_promotion_members,
        execution,
        &[],
    );

    assert!(result.is_err());
    let err = match result {
        Err(err) => err.to_string(),
        Ok(_) => panic!("expected invalid recipient verification error"),
    };
    assert!(err.contains("expired") || err.contains("self-signature"));
    assert_eq!(
        fs::read_to_string(&secret_path).unwrap(),
        plan.artifact_snapshots[0].content
    );
}
