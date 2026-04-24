// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::evaluate_member_removal;
use crate::app_test_utils::build_test_signing_command_options;
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::envelope::signature::SigningContext;
use crate::feature::kv::encrypt::encrypt_kv_document;
use crate::format::token::TokenCodec;
use crate::io::keystore::storage::{list_kids, load_public_key};
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{setup_member_key_context, setup_test_workspace_from_fixtures};
use serde_json::Value;
use tempfile::TempDir;

const ALICE_MEMBER_ID: &str = "alice@example.com";
const BOB_MEMBER_ID: &str = "bob@example.com";

fn build_verified_members(
    temp_dir: &TempDir,
    recipient_ids: &[&str],
) -> (
    crate::feature::context::crypto::CryptoContext,
    String,
    Vec<String>,
    Vec<crate::model::public_key::VerifiedRecipientKey>,
    crate::model::public_key::PublicKey,
) {
    let key_ctx = setup_member_key_context(temp_dir, ALICE_MEMBER_ID, None);
    let keystore_root = temp_dir.path().join("keys");
    let signer_kid = list_kids(&keystore_root, ALICE_MEMBER_ID)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let signer_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, &signer_kid).unwrap();
    let recipients = recipient_ids
        .iter()
        .map(|member_id| (*member_id).to_string())
        .collect::<Vec<_>>();
    let public_keys = recipient_ids
        .iter()
        .map(|member_id| {
            let kid = list_kids(&keystore_root, member_id).unwrap().remove(0);
            load_public_key(&keystore_root, member_id, &kid).unwrap()
        })
        .collect::<Vec<_>>();

    (
        key_ctx,
        signer_kid,
        recipients,
        build_verified_recipient_keys(&public_keys),
        signer_pub,
    )
}

fn save_file_artifact(
    workspace_dir: &Path,
    temp_dir: &TempDir,
    artifact_name: &str,
    recipient_ids: &[&str],
) {
    let (key_ctx, signer_kid, recipients, verified_members, signer_pub) =
        build_verified_members(temp_dir, recipient_ids);
    let document = encrypt_file_document(
        b"member-remove-preview",
        &recipients,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &signer_kid,
            signer_pub,
            debug: false,
        },
    )
    .unwrap();
    fs::write(
        workspace_dir.join("secrets").join(artifact_name),
        serde_json::to_string_pretty(&document).unwrap(),
    )
    .unwrap();
}

fn save_kv_artifact(
    workspace_dir: &Path,
    temp_dir: &TempDir,
    artifact_name: &str,
    recipient_ids: &[&str],
) {
    let (key_ctx, signer_kid, _recipients, verified_members, signer_pub) =
        build_verified_members(temp_dir, recipient_ids);
    let kv_map = HashMap::from([(String::from("API_KEY"), String::from("secret-value"))]);
    let content = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &signer_kid,
            signer_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();
    fs::write(workspace_dir.join("secrets").join(artifact_name), content).unwrap();
}

fn tamper_file_artifact_signature(workspace_dir: &Path, artifact_name: &str) {
    let artifact_path = workspace_dir.join("secrets").join(artifact_name);
    let mut document: Value =
        serde_json::from_str(&fs::read_to_string(&artifact_path).unwrap()).unwrap();
    document["protected"]["updated_at"] = Value::String("2026-01-01T00:00:01Z".to_string());
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&document).unwrap(),
    )
    .unwrap();
}

#[test]
fn test_evaluate_member_removal_detects_file_enc_recipient() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let artifact_path = workspace_dir.join("secrets").join("shared.json");
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "shared.json",
        &[ALICE_MEMBER_ID, BOB_MEMBER_ID],
    );
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let result = evaluate_member_removal(&options, BOB_MEMBER_ID).unwrap();

    assert_eq!(result.affected_artifacts.len(), 1);
    assert!(result.affected_artifacts[0].ends_with("shared.json"));
    assert_eq!(
        result.affected_artifacts[0].file_name(),
        artifact_path.file_name()
    );
    assert!(result.warnings.is_empty());
}

#[test]
fn test_evaluate_member_removal_detects_kv_enc_recipient() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let artifact_path = workspace_dir.join("secrets").join("default.kvenc");
    save_kv_artifact(
        &workspace_dir,
        &temp_dir,
        "default.kvenc",
        &[ALICE_MEMBER_ID, BOB_MEMBER_ID],
    );
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let result = evaluate_member_removal(&options, BOB_MEMBER_ID).unwrap();

    assert_eq!(result.affected_artifacts.len(), 1);
    assert!(result.affected_artifacts[0].ends_with("default.kvenc"));
    assert_eq!(
        result.affected_artifacts[0].file_name(),
        artifact_path.file_name()
    );
    assert!(result.warnings.is_empty());
}

#[test]
fn test_evaluate_member_removal_ignores_unrelated_artifact() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "alice-only.json",
        &[ALICE_MEMBER_ID],
    );
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let result = evaluate_member_removal(&options, BOB_MEMBER_ID).unwrap();

    assert!(result.affected_artifacts.is_empty());
    assert!(result.warnings.is_empty());
}

#[test]
fn test_evaluate_member_removal_collects_warning_for_invalid_artifact() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    fs::write(workspace_dir.join("secrets").join("broken.json"), "{broken").unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let result = evaluate_member_removal(&options, BOB_MEMBER_ID).unwrap();

    assert!(result.affected_artifacts.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("broken.json"));
}

#[test]
fn test_evaluate_member_removal_collects_warning_for_invalid_signature() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    save_file_artifact(
        &workspace_dir,
        &temp_dir,
        "tampered.json",
        &[ALICE_MEMBER_ID, BOB_MEMBER_ID],
    );
    tamper_file_artifact_signature(&workspace_dir, "tampered.json");
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let result = evaluate_member_removal(&options, BOB_MEMBER_ID).unwrap();

    assert!(result.affected_artifacts.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("tampered.json"));
    assert!(result.warnings[0].contains("Signature verification failed"));
}
