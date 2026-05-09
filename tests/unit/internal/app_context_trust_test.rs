// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;

use crate::app::member::approval::MemberApprovalResult;
use crate::app::trust::list::list_known_keys;
use crate::app::trust::{
    build_signer_identity, enforce_policy_strict_key_checking, enforce_recipients_trust,
    enforce_signer_trust, evaluate_signer_trust_with_proof, load_read_trust_context,
    CommandCapability, CommandTrustSnapshot, DecryptPolicy, EncryptPolicy, GetPolicy, ImportPolicy,
    RecipientTrustOutcome, RewrapInputPolicy, RunPolicy, SetPolicy, SignerTrustOutcome,
    TrustContext, UnsetPolicy,
};
use crate::app_test_utils::build_test_command_options;
use crate::config::types::{StrictKeyChecking, StrictKeyCheckingResolution};
use crate::feature::trust::judgment::{SelfTrustSet, TrustJudgment};
use crate::feature::trust::signature::sign_trust_store;
use crate::io::keystore::member::find_active_key_document;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::save_trust_store;
use crate::model::public_key::{
    Attestation, BindingClaims, GithubAccount, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey,
    PublicKeyProtected,
};
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use crate::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use crate::model::wire::format::LOCAL_TRUST_V5;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{
    kid, member_handle, save_active_public_key_to_workspace, save_public_key,
    setup_test_keystore_from_fixtures, update_active_private_key_expires_at,
};

const VALID_TEST_KID: &str = "KAD1AAAA1111BBBB2222CCCC3333DDDD";

fn build_test_trust_ctx(strict: StrictKeyChecking, interactive: bool) -> TrustContext {
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

fn build_public_key(member_handle: &str, kid: &str, sig_x: &str) -> PublicKey {
    let kid = match kid {
        "KID1AAAA1111BBBB2222CCCC3333DDDD" => VALID_TEST_KID,
        _ => kid,
    };
    let sig_x = match sig_x {
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" => {
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
        }
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" => {
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
        }
        _ => sig_x,
    };

    PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv:format:public-key@6".to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "X25519".to_string(),
                        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: sig_x.to_string(),
                    },
                },
                attestation: Attestation {
                    method: "ssh".to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey".to_string(),
                    sig: "test-signature".to_string(),
                },
            },
            binding_claims: Some(BindingClaims {
                github_account: Some(GithubAccount {
                    id: 42,
                    login: "octocat".to_string(),
                }),
            }),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "self-signature".to_string(),
    }
}

fn build_known_key(kid: &str, member_handle: &str) -> KnownKey {
    let kid = match kid {
        "KID1AAAA1111BBBB2222CCCC3333DDDD" => VALID_TEST_KID,
        _ => kid,
    };
    KnownKey {
        kid: kid.to_string(),
        subject_handle: member_handle.to_string(),
        approved_at: "2026-01-01T00:00:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

#[test]
fn test_enforce_signer_trust_trusted() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let public_key = build_public_key(
        "alice@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    );

    let result = enforce_signer_trust(
        &ctx,
        &TrustJudgment::Trusted,
        &public_key,
        CommandCapability::Decrypt,
        &[],
    )
    .unwrap();

    assert_eq!(result, SignerTrustOutcome::Accepted);
}

#[test]
fn test_enforce_recipients_trust_self_trust_set_skips_local_nonactive_self_key() {
    let mut ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    ctx.self_trust = SelfTrustSet::new("alice@example.com", [[1u8; 32], [2u8; 32]]);
    let recipients = vec![
        build_public_key(
            "alice@example.com",
            "KID1AAAA1111BBBB2222CCCC3333DDDD",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        ),
        build_public_key(
            "bob@example.com",
            "KID1AAAA1111BBBB2222CCCC3333DDDD",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        ),
    ];

    let result = enforce_recipients_trust(&ctx, &recipients).unwrap();

    match result {
        RecipientTrustOutcome::NeedsManualApproval(pending) => {
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].member_handle, "bob@example.com");
        }
        other => panic!("unexpected outcome: {:?}", other),
    }
}

#[test]
fn test_command_trust_snapshot_loads_local_nonactive_self_key() {
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    let keystore_root = dir.path().join("keys");
    let mut local_nonactive = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key fixture")
        .public_key;
    local_nonactive.protected.kid = "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string();
    local_nonactive.protected.identity.keys.sig.x =
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string();
    save_public_key(
        &keystore_root,
        ALICE_MEMBER_HANDLE,
        &local_nonactive.protected.kid,
        &local_nonactive,
    )
    .unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));

    let snapshot = CommandTrustSnapshot::<EncryptPolicy>::load(
        &options,
        &workspace,
        ALICE_MEMBER_HANDLE,
        None,
        false,
    )
    .unwrap();
    let identity = build_signer_identity(&local_nonactive).unwrap();

    assert!(snapshot
        .trust_context()
        .self_trust
        .contains_identity(&identity)
        .unwrap());
}

#[test]
fn test_command_trust_snapshot_defers_unreferenced_local_self_key_loading() {
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    let keystore_root = dir.path().join("keys");
    let broken_kid = "KCD3AAAA1111BBBB2222CCCC3333DDDD";
    let broken_dir = keystore_root.join(ALICE_MEMBER_HANDLE).join(broken_kid);
    fs::create_dir_all(&broken_dir).unwrap();
    fs::write(broken_dir.join("public.json"), b"{not-json").unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));

    let snapshot = CommandTrustSnapshot::<EncryptPolicy>::load(
        &options,
        &workspace,
        ALICE_MEMBER_HANDLE,
        None,
        false,
    )
    .unwrap();
    let active = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key fixture");
    let identity = build_signer_identity(&active.public_key).unwrap();

    assert!(snapshot
        .trust_context()
        .self_trust
        .contains_identity(&identity)
        .unwrap());
}

#[test]
fn test_evaluate_signer_trust_with_proof_accepts_historical_self_key() {
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    let keystore_root = dir.path().join("keys");
    let mut local_nonactive = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key fixture")
        .public_key;
    local_nonactive.protected.kid = "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string();
    local_nonactive.protected.identity.keys.sig.x =
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string();
    save_public_key(
        &keystore_root,
        ALICE_MEMBER_HANDLE,
        &local_nonactive.protected.kid,
        &local_nonactive,
    )
    .unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let snapshot = CommandTrustSnapshot::<DecryptPolicy>::load(
        &options,
        &workspace,
        ALICE_MEMBER_HANDLE,
        None,
        false,
    )
    .unwrap();
    let proof = SignatureVerificationProof::new_with_signer_public_key(
        local_nonactive.protected.subject_handle.clone(),
        local_nonactive.protected.kid.clone(),
        local_nonactive.clone(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );

    let result = evaluate_signer_trust_with_proof(
        snapshot.trust_context(),
        &proof,
        CommandCapability::Decrypt,
        &[],
    )
    .unwrap();

    assert_eq!(result, SignerTrustOutcome::Accepted);
}

#[test]
fn test_evaluate_signer_trust_with_proof_accepts_historical_self_key_for_run() {
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    let keystore_root = dir.path().join("keys");
    let mut local_nonactive = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key fixture")
        .public_key;
    local_nonactive.protected.kid = "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string();
    local_nonactive.protected.identity.keys.sig.x =
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string();
    save_public_key(
        &keystore_root,
        ALICE_MEMBER_HANDLE,
        &local_nonactive.protected.kid,
        &local_nonactive,
    )
    .unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));
    let snapshot = CommandTrustSnapshot::<RunPolicy>::load(
        &options,
        &workspace,
        ALICE_MEMBER_HANDLE,
        None,
        false,
    )
    .unwrap();
    let proof = SignatureVerificationProof::new_with_signer_public_key(
        local_nonactive.protected.subject_handle.clone(),
        local_nonactive.protected.kid.clone(),
        local_nonactive.clone(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );

    let result = evaluate_signer_trust_with_proof(
        snapshot.trust_context(),
        &proof,
        CommandCapability::Run,
        &[],
    )
    .unwrap();

    assert_eq!(result, SignerTrustOutcome::Accepted);
}

#[test]
fn test_load_read_trust_context_allows_expired_active_member_with_warning() {
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    update_active_private_key_expires_at(dir.path(), ALICE_MEMBER_HANDLE, "2020-01-01T00:00:00Z");
    save_active_public_key_to_workspace(dir.path(), &workspace, ALICE_MEMBER_HANDLE).unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));

    let loaded =
        load_read_trust_context(&options, &workspace, ALICE_MEMBER_HANDLE, None, false).unwrap();

    assert_eq!(loaded.trust_ctx.active_members_by_kid.len(), 1);
    assert!(loaded
        .warnings
        .iter()
        .any(|warning| warning.contains("expired")));
}

#[test]
fn test_write_trust_snapshot_rejects_expired_active_member() {
    let dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let workspace = dir.path().join("workspace");
    update_active_private_key_expires_at(dir.path(), ALICE_MEMBER_HANDLE, "2020-01-01T00:00:00Z");
    save_active_public_key_to_workspace(dir.path(), &workspace, ALICE_MEMBER_HANDLE).unwrap();
    let options = build_test_command_options(dir.path(), Some(&workspace));

    let error = CommandTrustSnapshot::<EncryptPolicy>::load(
        &options,
        &workspace,
        ALICE_MEMBER_HANDLE,
        None,
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("expired"));
}

#[test]
fn test_enforce_signer_trust_needs_known_key_approval_interactive() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let public_key = build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let judgment = TrustJudgment::NeedsApproval {
        member_handle: member_handle(public_key.protected.subject_handle.clone()),
        kid: kid(public_key.protected.kid.clone()),
    };

    let result = enforce_signer_trust(
        &ctx,
        &judgment,
        &public_key,
        CommandCapability::Decrypt,
        &[],
    )
    .unwrap();

    match result {
        SignerTrustOutcome::NeedsKnownKeyApproval(candidate) => {
            assert_eq!(candidate.member_handle, "bob@example.com");
            assert_eq!(candidate.kid, VALID_TEST_KID);
            assert_eq!(candidate.github_id, None);
            assert_eq!(candidate.github_login.as_deref(), None);
            assert!(candidate.github_binding_configured);
        }
        other => panic!("unexpected outcome: {:?}", other),
    }
}

#[test]
fn test_enforce_signer_trust_needs_known_key_approval_non_interactive_fails() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, false);
    let public_key = build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let judgment = TrustJudgment::NeedsApproval {
        member_handle: member_handle(public_key.protected.subject_handle.clone()),
        kid: kid(public_key.protected.kid.clone()),
    };

    let result = enforce_signer_trust(
        &ctx,
        &judgment,
        &public_key,
        CommandCapability::Decrypt,
        &[],
    );

    assert!(result.is_err());
}

#[test]
fn test_enforce_signer_trust_strict_no_non_interactive_accepted() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::No, false);
    let public_key = build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let judgment = TrustJudgment::NeedsApproval {
        member_handle: member_handle(public_key.protected.subject_handle.clone()),
        kid: kid(public_key.protected.kid.clone()),
    };

    let result = enforce_signer_trust(
        &ctx,
        &judgment,
        &public_key,
        CommandCapability::Decrypt,
        &[],
    )
    .unwrap();

    assert_eq!(result, SignerTrustOutcome::Accepted);
}

#[test]
fn test_enforce_signer_trust_strict_no_interactive_accepted() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::No, true);
    let public_key = build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let judgment = TrustJudgment::NeedsApproval {
        member_handle: member_handle(public_key.protected.subject_handle.clone()),
        kid: kid(public_key.protected.kid.clone()),
    };

    let result = enforce_signer_trust(
        &ctx,
        &judgment,
        &public_key,
        CommandCapability::Decrypt,
        &[],
    )
    .unwrap();

    assert_eq!(result, SignerTrustOutcome::Accepted);
}

#[test]
fn test_enforce_signer_trust_strict_no_write_path_fails() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::No, false);
    let public_key = build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );

    let result = enforce_signer_trust(
        &ctx,
        &TrustJudgment::Trusted,
        &public_key,
        CommandCapability::Set,
        &[],
    );

    assert!(result.is_err());
}

#[test]
fn test_enforce_signer_trust_non_member_decrypt_interactive() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let public_key = build_public_key(
        "ex-member@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let judgment = TrustJudgment::NonMember {
        member_handle: member_handle(public_key.protected.subject_handle.clone()),
        kid: kid(public_key.protected.kid.clone()),
    };
    let recipients = vec![
        "alice@example.com".to_string(),
        "bob@example.com".to_string(),
    ];

    let result = enforce_signer_trust(
        &ctx,
        &judgment,
        &public_key,
        CommandCapability::Decrypt,
        &recipients,
    )
    .unwrap();

    match result {
        SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate,
            current_recipients,
        } => {
            assert_eq!(candidate.member_handle, "ex-member@example.com");
            assert_eq!(current_recipients, recipients);
        }
        other => panic!("unexpected outcome: {:?}", other),
    }
}

#[test]
fn test_enforce_signer_trust_non_member_forbidden_command_fails() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let public_key = build_public_key(
        "ex-member@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let judgment = TrustJudgment::NonMember {
        member_handle: member_handle(public_key.protected.subject_handle.clone()),
        kid: kid(public_key.protected.kid.clone()),
    };

    let result = enforce_signer_trust(&ctx, &judgment, &public_key, CommandCapability::Run, &[]);

    assert!(result.is_err());
}

#[test]
fn test_evaluate_signer_trust_with_proof_uses_embedded_signer_public_key() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let public_key = build_public_key(
        "ex-member@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let proof = SignatureVerificationProof::new_with_signer_public_key(
        public_key.protected.subject_handle.clone(),
        public_key.protected.kid.clone(),
        public_key.clone(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );

    let result = evaluate_signer_trust_with_proof(
        &ctx,
        &proof,
        CommandCapability::Decrypt,
        &["alice@example.com".to_string()],
    )
    .unwrap();

    match result {
        SignerTrustOutcome::NeedsNonMemberAcceptance { candidate, .. } => {
            assert_eq!(candidate.member_handle, public_key.protected.subject_handle);
            assert_eq!(candidate.kid, public_key.protected.kid);
        }
        other => panic!("unexpected outcome: {:?}", other),
    }
}

#[test]
fn test_evaluate_signer_trust_with_proof_missing_signer_pub_fails() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let proof = SignatureVerificationProof::new(
        "alice@example.com".to_string(),
        "KID1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );

    let error = evaluate_signer_trust_with_proof(&ctx, &proof, CommandCapability::Decrypt, &[])
        .unwrap_err();

    assert!(error.format_user_message().contains("signer_pub"));
}

#[test]
fn test_enforce_signer_trust_kid_integrity_anomaly() {
    let mut ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let public_key = build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    ctx.known_keys.push(build_known_key(
        &public_key.protected.kid,
        "alice@example.com",
    ));
    let judgment = TrustJudgment::KnownKeyIntegrityAnomaly {
        member_handle: member_handle(public_key.protected.subject_handle.clone()),
        kid: kid(public_key.protected.kid.clone()),
        known_member_handle: member_handle("alice@example.com"),
    };

    let result = enforce_signer_trust(
        &ctx,
        &judgment,
        &public_key,
        CommandCapability::Decrypt,
        &[],
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("subject_handle"));
}

#[test]
fn test_enforce_recipients_trust_accepts_empty_recipients() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);

    let result = enforce_recipients_trust(&ctx, &[]).unwrap();

    assert_eq!(result, RecipientTrustOutcome::Accepted);
}

#[test]
fn test_enforce_recipients_trust_interactive_requires_manual_approval() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    let recipients = vec![build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    )];

    let result = enforce_recipients_trust(&ctx, &recipients).unwrap();

    match result {
        RecipientTrustOutcome::NeedsManualApproval(pending) => {
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].member_handle, "bob@example.com");
        }
        other => panic!("unexpected outcome: {:?}", other),
    }
}

#[test]
fn test_enforce_recipients_trust_non_interactive_hard_fail() {
    let ctx = build_test_trust_ctx(StrictKeyChecking::Yes, false);
    let recipients = vec![build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    )];

    let result = enforce_recipients_trust(&ctx, &recipients);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("member verify --approve"));
}

#[test]
fn test_enforce_recipients_trust_detects_kid_integrity_mismatch() {
    let mut ctx = build_test_trust_ctx(StrictKeyChecking::Yes, true);
    ctx.known_keys = vec![build_known_key(
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "alice@example.com",
    )];
    let recipients = vec![build_public_key(
        "bob@example.com",
        "KID1AAAA1111BBBB2222CCCC3333DDDD",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    )];

    let result = enforce_recipients_trust(&ctx, &recipients);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("candidate has member_handle 'bob@example.com'"));
}

#[test]
fn test_non_member_acceptance_allowed_commands() {
    assert!(CommandCapability::Decrypt.allows_non_member_acceptance());
    assert!(CommandCapability::Get.allows_non_member_acceptance());
    assert!(CommandCapability::Rewrap.allows_non_member_acceptance());
}

#[test]
fn test_non_member_acceptance_forbidden_commands() {
    assert!(!CommandCapability::Run.allows_non_member_acceptance());
    assert!(!CommandCapability::Set.allows_non_member_acceptance());
    assert!(!CommandCapability::Unset.allows_non_member_acceptance());
    assert!(!CommandCapability::Import.allows_non_member_acceptance());
}

#[test]
fn test_policy_strict_key_checking_no_allowed_for_read_paths() {
    assert!(CommandCapability::Decrypt.allows_strict_key_checking_no());
    assert!(CommandCapability::Get.allows_strict_key_checking_no());
    assert!(CommandCapability::Run.allows_strict_key_checking_no());
    let strict_no = StrictKeyCheckingResolution::explicit(StrictKeyChecking::No);

    enforce_policy_strict_key_checking::<DecryptPolicy>(strict_no).unwrap();
    enforce_policy_strict_key_checking::<GetPolicy>(strict_no).unwrap();
    enforce_policy_strict_key_checking::<RunPolicy>(strict_no).unwrap();
}

#[test]
fn test_policy_strict_key_checking_no_rejected_for_write_paths_and_rewrap() {
    assert!(!CommandCapability::Encrypt.allows_strict_key_checking_no());
    assert!(!CommandCapability::Set.allows_strict_key_checking_no());
    assert!(!CommandCapability::Unset.allows_strict_key_checking_no());
    assert!(!CommandCapability::Import.allows_strict_key_checking_no());
    assert!(!CommandCapability::Rewrap.allows_strict_key_checking_no());
    let strict_no = StrictKeyCheckingResolution::explicit(StrictKeyChecking::No);

    assert!(enforce_policy_strict_key_checking::<EncryptPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<SetPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<UnsetPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<ImportPolicy>(strict_no).is_err());
    assert!(enforce_policy_strict_key_checking::<RewrapInputPolicy>(strict_no).is_err());
}

#[test]
fn test_env_key_mode_allowed_commands() {
    assert!(CommandCapability::Decrypt.allows_env_key_mode());
    assert!(CommandCapability::Get.allows_env_key_mode());
    assert!(CommandCapability::List.allows_env_key_mode());
    assert!(CommandCapability::Run.allows_env_key_mode());
    assert!(!CommandCapability::Encrypt.allows_env_key_mode());
    assert!(!CommandCapability::Init.allows_env_key_mode());
    assert!(!CommandCapability::Set.allows_env_key_mode());
    assert!(!CommandCapability::Trust.allows_env_key_mode());
}

#[test]
fn test_trust_list_no_trust_store_returns_empty() {
    let dir = tempfile::TempDir::new().unwrap();
    let options = build_test_command_options(dir.path(), None);

    let result = list_known_keys(&options, "nobody@example.com").unwrap();

    assert!(result.items.is_empty());
    assert!(result.warnings.is_empty());
}

#[cfg(unix)]
#[test]
fn test_trust_list_surfaces_insecure_permission_warning() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, _workspace) =
        crate::test_utils::setup_test_workspace_from_fixtures(&["alice@example.com"]);
    let owner_handle = "alice@example.com";
    let key_ctx = crate::test_utils::setup_member_key_context(&dir, owner_handle, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V5.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: vec![build_known_key(&key_ctx.kid, owner_handle)],
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, &key_ctx.signing_key, &key_ctx.kid).unwrap();
    let trust_path = get_trust_store_file_path(dir.path(), owner_handle);
    save_trust_store(&trust_path, &document).unwrap();
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let options = build_test_command_options(dir.path(), None);

    let result = list_known_keys(&options, owner_handle).unwrap();

    assert!(!result.warnings.is_empty());
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("Insecure permissions")));
}

#[test]
fn test_manual_approval_result_fields() {
    let result = MemberApprovalResult {
        member_handle: "ssh-only@example.com".to_string(),
        kid: "KID1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        verified: false,
        approved: true,
        review_required: false,
        already_known: false,
        message: "No GitHub binding configured".to_string(),
        fingerprint: Some("SHA256:abc".to_string()),
        github_id: None,
        github_login: None,
        github_binding_configured: false,
        attestor_pub: None,
        verified_github: None,
    };

    let status = match (
        result.verified,
        result.approved,
        result.review_required,
        result.already_known,
    ) {
        (_, true, _, _) => "approved",
        (_, _, _, true) => "already known",
        (_, _, true, false) => "pending review",
        _ => "not verified",
    };

    assert_eq!(status, "approved");
}
