// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::trust::enforcement::{
    enforce_artifact_recipient_set_trust, evaluate_read_artifact_recipient_keys,
    ArtifactRecipientTrustOutcome, RecipientTrustOutcome,
};
use crate::app::trust::{CommandCapability, TrustContext};
use crate::config::types::{StrictKeyChecking, StrictKeyCheckingResolution};
use crate::feature::trust::judgment::SelfTrustSet;
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::model::common::WrapItem;
use crate::model::public_key::{
    Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};
use crate::model::trust_store::RecipientSetRecord;
use crate::Error;
use uuid::Uuid;

const ALICE_KID: &str = "KAD1AAAA1111BBBB2222CCCC3333DDDD";
const BOB_KID: &str = "KBD2AAAA1111BBBB2222CCCC3333DDDD";

#[test]
fn test_recipient_set_trust_accepts_reviewed_set_when_signer_is_member() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::Yes, false);
    trust_ctx.recipient_sets = vec![record_from_set(&current)];

    let outcome = enforce_artifact_recipient_set_trust(
        &trust_ctx,
        ALICE_KID,
        &current,
        CommandCapability::Get,
    )
    .unwrap();

    assert_eq!(outcome, ArtifactRecipientTrustOutcome::Accepted);
}

#[test]
fn test_recipient_set_trust_rejects_reviewed_set_when_signer_is_not_member() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::Yes, false);
    trust_ctx.recipient_sets = vec![record_from_set(&current)];

    let error =
        enforce_artifact_recipient_set_trust(&trust_ctx, BOB_KID, &current, CommandCapability::Get)
            .unwrap_err();

    assert_verify_rule(error, "E_RECIPIENT_SET_SIGNER_NOT_INCLUDED");
}

#[test]
fn test_recipient_set_review_rejects_changed_set_when_signer_is_not_member() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let approved = recipient_set(&[("bob@example.com", BOB_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::Yes, true);
    trust_ctx.recipient_sets = vec![record_from_set(&approved)];

    let error =
        enforce_artifact_recipient_set_trust(&trust_ctx, BOB_KID, &current, CommandCapability::Get)
            .unwrap_err();

    assert_verify_rule(error, "E_RECIPIENT_SET_SIGNER_NOT_INCLUDED");
}

#[test]
fn test_recipient_set_review_allows_missing_set_when_signer_is_member() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let trust_ctx = trust_ctx(StrictKeyChecking::Yes, true);

    let outcome = enforce_artifact_recipient_set_trust(
        &trust_ctx,
        ALICE_KID,
        &current,
        CommandCapability::Get,
    )
    .unwrap();

    assert!(matches!(
        outcome,
        ArtifactRecipientTrustOutcome::NeedsManualApproval(_)
    ));
}

#[test]
fn test_recipient_set_review_auto_accepts_missing_self_only_set() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::Yes, false);
    trust_ctx.self_trust = SelfTrustSet::new("alice@example.com", [[0u8; 32]]);
    trust_ctx.active_members_by_kid.insert(
        ALICE_KID.to_string(),
        active_member("alice@example.com", ALICE_KID),
    );

    let outcome = enforce_artifact_recipient_set_trust(
        &trust_ctx,
        ALICE_KID,
        &current,
        CommandCapability::Get,
    )
    .unwrap();

    assert_eq!(outcome, ArtifactRecipientTrustOutcome::Accepted);
}

#[test]
fn test_recipient_set_review_auto_accepts_changed_self_only_set() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let approved = recipient_set(&[("bob@example.com", BOB_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::Yes, false);
    trust_ctx.self_trust = SelfTrustSet::new("alice@example.com", [[0u8; 32]]);
    trust_ctx.active_members_by_kid.insert(
        ALICE_KID.to_string(),
        active_member("alice@example.com", ALICE_KID),
    );
    trust_ctx.recipient_sets = vec![record_from_set(&approved)];

    let outcome = enforce_artifact_recipient_set_trust(
        &trust_ctx,
        ALICE_KID,
        &current,
        CommandCapability::Get,
    )
    .unwrap();

    assert_eq!(outcome, ArtifactRecipientTrustOutcome::Accepted);
}

#[test]
fn test_strict_key_checking_no_skips_recipient_member_set_check() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let trust_ctx = trust_ctx(StrictKeyChecking::No, false);

    let outcome =
        enforce_artifact_recipient_set_trust(&trust_ctx, BOB_KID, &current, CommandCapability::Get)
            .unwrap();

    assert_eq!(
        outcome,
        ArtifactRecipientTrustOutcome::SkippedStrictKeyCheckingNo
    );
}

#[test]
fn test_recipient_set_trust_rejects_active_member_handle_mismatch() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::Yes, true);
    trust_ctx.active_members_by_kid.insert(
        ALICE_KID.to_string(),
        active_member("bob@example.com", ALICE_KID),
    );

    let error = enforce_artifact_recipient_set_trust(
        &trust_ctx,
        ALICE_KID,
        &current,
        CommandCapability::Get,
    )
    .unwrap_err();

    assert_verify_rule(error, "E_RECIPIENT_SET_HANDLE_MISMATCH");
}

#[test]
fn test_strict_key_checking_no_rejects_active_member_handle_mismatch() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::No, false);
    trust_ctx.active_members_by_kid.insert(
        ALICE_KID.to_string(),
        active_member("bob@example.com", ALICE_KID),
    );

    let error =
        enforce_artifact_recipient_set_trust(&trust_ctx, BOB_KID, &current, CommandCapability::Get)
            .unwrap_err();

    assert_verify_rule(error, "E_RECIPIENT_SET_HANDLE_MISMATCH");
}

#[test]
fn test_read_recipient_keys_warns_for_unresolved_recipient_kid() {
    let current = recipient_set(&[
        ("alice@example.com", ALICE_KID),
        ("former@example.com", BOB_KID),
    ]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::Yes, true);
    trust_ctx.active_members_by_kid.insert(
        ALICE_KID.to_string(),
        active_member("alice@example.com", ALICE_KID),
    );

    let result = evaluate_read_artifact_recipient_keys(&trust_ctx, ALICE_KID, &current).unwrap();

    assert_eq!(
        result.outcome,
        RecipientTrustOutcome::NeedsManualApproval(vec![
            crate::app::trust::enforcement::build_trust_approval_candidate(
                trust_ctx.active_members_by_kid.get(ALICE_KID).unwrap()
            )
        ])
    );
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains(BOB_KID));
    assert!(result.warnings[0].contains("rewrap"));
}

#[test]
fn test_read_recipient_keys_rejects_signer_not_in_recipient_set_even_strict_no() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let trust_ctx = trust_ctx(StrictKeyChecking::No, false);

    let error = evaluate_read_artifact_recipient_keys(&trust_ctx, BOB_KID, &current).unwrap_err();

    assert_verify_rule(error, "E_RECIPIENT_SET_SIGNER_NOT_INCLUDED");
}

#[test]
fn test_read_recipient_keys_strict_no_keeps_validation_but_skips_key_review() {
    let current = recipient_set(&[("alice@example.com", ALICE_KID)]);
    let mut trust_ctx = trust_ctx(StrictKeyChecking::No, false);
    trust_ctx.active_members_by_kid.insert(
        ALICE_KID.to_string(),
        active_member("alice@example.com", ALICE_KID),
    );

    let result = evaluate_read_artifact_recipient_keys(&trust_ctx, ALICE_KID, &current).unwrap();

    assert_eq!(result.outcome, RecipientTrustOutcome::Accepted);
    assert!(result.warnings.is_empty());
}

fn trust_ctx(strict: StrictKeyChecking, interactive: bool) -> TrustContext {
    TrustContext {
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
        active_members_by_kid: BTreeMap::new(),
        self_trust: SelfTrustSet::default(),
        strict_key_checking: StrictKeyCheckingResolution::explicit(strict),
        is_interactive: interactive,
        permission_warnings: Vec::new(),
    }
}

fn active_member(member_handle: &str, kid: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv:format:public-key@6".to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: public_key("X25519"),
                    sig: public_key("Ed25519"),
                },
                attestation: Attestation {
                    method: "ssh".to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey".to_string(),
                    sig: "test-signature".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "self-signature".to_string(),
    }
}

fn public_key(crv: &str) -> JwkOkpPublicKey {
    JwkOkpPublicKey {
        kty: "OKP".to_string(),
        crv: crv.to_string(),
        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
}

fn recipient_set(items: &[(&str, &str)]) -> ArtifactRecipientSet {
    let wrap_items = items
        .iter()
        .map(|(recipient_handle, kid)| wrap_item(recipient_handle, kid))
        .collect::<Vec<_>>();
    ArtifactRecipientSet::from_wrap_items(Uuid::nil(), &wrap_items).unwrap()
}

fn record_from_set(set: &ArtifactRecipientSet) -> RecipientSetRecord {
    set.clone().into_record("2026-05-01T00:00:00Z".to_string())
}

fn wrap_item(recipient_handle: &str, kid: &str) -> WrapItem {
    WrapItem {
        recipient_handle: recipient_handle.to_string(),
        kid: kid.to_string(),
        alg: "hpke-32-1-3".to_string(),
        enc: "enc".to_string(),
        ct: "ct".to_string(),
    }
}

fn assert_verify_rule(error: Error, expected_rule: &str) {
    match error {
        Error::Verify { rule, .. } => assert_eq!(rule, expected_rule),
        other => panic!("expected verify error, got {other:?}"),
    }
}
