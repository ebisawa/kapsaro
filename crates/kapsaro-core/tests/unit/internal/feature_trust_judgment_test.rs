// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust judgment logic

use crate::feature::trust::judgment::{
    judge_recipients_trust, judge_signer_trust, ActiveMemberSnapshot, KnownKeyCache, SelfTrustSet,
    TrustIdentity, TrustJudgment,
};
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia};
use crate::test_support::storage::keystore::storage::{list_kids, load_public_key};
use crate::test_utils::{setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE};
use std::collections::BTreeMap;
use tempfile::TempDir;

/// No key of this shape is ever listed in the set, so it is the keystore that
/// has to answer for it.
const NO_LISTED_KEYS: [[u8; 32]; 0] = [];

const KID1: &str = "KAD1AAAA1111BBBB2222CCCC3333DDDD";
const KID2: &str = "KBD2AAAA1111BBBB2222CCCC3333DDDD";
/// The same key id as `KID1`, spelled the way it is shown to an operator. A
/// stored document never carries this form.
const KID1_DISPLAY_FORM: &str = "kad1-aaaa-1111-bbbb-2222-cccc-3333-dddd";

fn member_handle(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).unwrap()
}

fn kid_value(value: &str) -> Kid {
    Kid::try_from(value).unwrap()
}

fn build_known_key(kid: &str, member_handle: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        subject_handle: member_handle.to_string(),
        approved_at: "2026-03-29T12:40:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn build_active_members(entries: &[(&str, &str)]) -> BTreeMap<String, PublicKey> {
    let mut map = BTreeMap::new();
    for (kid, member_handle) in entries {
        let pk: PublicKey =
            serde_json::from_str(&minimal_public_key_json(kid, member_handle)).unwrap();
        map.insert(kid.to_string(), pk);
    }
    map
}

/// The smallest public key document a judgment can be made about.
///
/// Both key values decode to exactly 32 bytes with no unused tail bits set, so
/// a test that reads the document rather than only its labels gets a key it can
/// decode instead of a base64 the strict decoder refuses.
fn minimal_public_key_json(kid: &str, member_handle: &str) -> String {
    format!(
        r#"{{
        "protected": {{
            "format": "kapsaro:format:public-key@1",
            "subject_handle": "{}",
            "kid": "{}",
            "keys": {{
                "kem": {{ "kty": "OKP", "crv": "X25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }},
                "sig": {{ "kty": "OKP", "crv": "Ed25519", "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA" }}
            }},
            "attestation": {{
                "method": "ssh",
                "pub": "ssh-ed25519 test",
                "sig": "test"
            }},
            "expires_at": "2030-01-01T00:00:00Z"
        }},
        "signature": "test_sig"
    }}"#,
        member_handle, kid
    )
}

#[test]
fn test_judge_signer_trust_trusted() {
    let kid = KID1;
    let active = build_active_members(&[(kid, "bob")]);
    let known = vec![build_known_key(kid, "bob")];
    let signer = TrustIdentity::new("bob", kid, [0u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(result, TrustJudgment::Trusted);
}

#[test]
fn test_judge_signer_trust_needs_approval() {
    let kid = KID1;
    let active = build_active_members(&[(kid, "bob")]);
    let known: Vec<KnownKey> = vec![];
    let signer = TrustIdentity::new("bob", kid, [0u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(
        result,
        TrustJudgment::NeedsApproval {
            member_handle: member_handle("bob"),
            kid: kid_value(kid),
        }
    );
}

#[test]
fn test_judge_signer_trust_non_member() {
    let kid = KID1;
    let active: BTreeMap<String, PublicKey> = BTreeMap::new();
    let known = vec![build_known_key(kid, "bob")];
    let signer = TrustIdentity::new("bob", kid, [0u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(
        result,
        TrustJudgment::NonMember {
            member_handle: member_handle("bob"),
            kid: kid_value(kid),
        }
    );
}

#[test]
fn test_judge_signer_trust_self_exception_skips_known_keys() {
    let kid = KID1;
    let active = build_active_members(&[(kid, "self")]);
    let known: Vec<KnownKey> = vec![];
    let self_keys = SelfTrustSet::new("self", [[42u8; 32]]);
    let signer = TrustIdentity::new("self", kid, [42u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &self_keys,
    )
    .unwrap();
    assert_eq!(result, TrustJudgment::Trusted);
}

#[test]
fn test_judge_signer_trust_self_trust_set_skips_known_keys() {
    let kid = KID1;
    let active = build_active_members(&[(kid, "self")]);
    let known: Vec<KnownKey> = vec![];
    let self_keys = SelfTrustSet::new("self", [[42u8; 32], [99u8; 32]]);
    let signer = TrustIdentity::new("self", kid, [99u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &self_keys,
    )
    .unwrap();
    assert_eq!(result, TrustJudgment::Trusted);
}

#[test]
fn test_judge_signer_trust_self_trust_set_not_matched() {
    let kid = KID1;
    let active = build_active_members(&[(kid, "other")]);
    let known: Vec<KnownKey> = vec![];
    let self_keys = SelfTrustSet::new("self", [[42u8; 32]]);
    let signer = TrustIdentity::new("other", kid, [99u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &self_keys,
    )
    .unwrap();
    assert_eq!(
        result,
        TrustJudgment::NeedsApproval {
            member_handle: member_handle("other"),
            kid: kid_value(kid),
        }
    );
}

#[test]
fn test_judge_signer_trust_self_trust_set_accepts_historical_self_key() {
    let kid = KID1;
    let active: BTreeMap<String, PublicKey> = BTreeMap::new();
    let known: Vec<KnownKey> = vec![];
    let self_keys = SelfTrustSet::new("self", [[42u8; 32], [99u8; 32]]);
    let signer = TrustIdentity::new("self", kid, [99u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &self_keys,
    )
    .unwrap();
    assert_eq!(result, TrustJudgment::Trusted);
}

// === Regression: kid cached with a different member_handle ===

#[test]
fn test_judge_signer_trust_cached_kid_different_member_integrity_anomaly() {
    // known_keys has K1 -> alice, but workspace presents K1 for bob
    let kid = KID1;
    let active = build_active_members(&[(kid, "bob")]);
    let known = vec![build_known_key(kid, "alice")];
    let signer = TrustIdentity::new("bob", kid, [0u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(
        result,
        TrustJudgment::KnownKeyIntegrityAnomaly {
            member_handle: member_handle("bob"),
            kid: kid_value(kid),
            known_member_handle: member_handle("alice"),
        }
    );
}

#[test]
fn test_judge_signer_trust_cached_kid_same_member_trusted() {
    let kid = KID1;
    let active = build_active_members(&[(kid, "alice")]);
    let known = vec![build_known_key(kid, "alice")];
    let signer = TrustIdentity::new("alice", kid, [0u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(result, TrustJudgment::Trusted);
}

#[test]
fn test_judge_signer_trust_member_handle_mismatch_is_not_current_member() {
    let kid = KID1;
    let active = build_active_members(&[(kid, "alice@example.com")]);
    let known = vec![build_known_key(kid, "bob@example.com")];
    let signer = TrustIdentity::new("bob@example.com", kid, [0u8; 32]);

    let result = judge_signer_trust(
        &signer,
        &ActiveMemberSnapshot::new(&active),
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(
        result,
        TrustJudgment::ActiveMemberMismatch {
            member_handle: member_handle("bob@example.com"),
            kid: kid_value(kid),
            active_member_handle: member_handle("alice@example.com"),
        }
    );
}

// === Recipients trust tests ===

#[test]
fn test_judge_recipients_trust_all_known() {
    let known = vec![build_known_key(KID1, "alice"), build_known_key(KID2, "bob")];
    let recipients = vec![
        TrustIdentity::new("alice", KID1, [0u8; 32]),
        TrustIdentity::new("bob", KID2, [1u8; 32]),
    ];

    let needs = judge_recipients_trust(
        &recipients,
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert!(needs.is_empty());
}

#[test]
fn test_judge_recipients_trust_unknown_kid() {
    let known: Vec<KnownKey> = vec![];
    let recipients = vec![TrustIdentity::new("bob", KID1, [0u8; 32])];

    let needs = judge_recipients_trust(
        &recipients,
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].member_handle(), "bob");
}

#[test]
fn test_judge_recipients_trust_cached_kid_different_member() {
    let known = vec![build_known_key(KID1, "alice")];
    let recipients = vec![TrustIdentity::new("bob", KID1, [0u8; 32])];

    let needs = judge_recipients_trust(
        &recipients,
        &KnownKeyCache::new(&known),
        &SelfTrustSet::default(),
    )
    .unwrap();
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].member_handle(), "bob");
}

#[test]
fn test_judge_recipients_trust_self_exception_skips() {
    let known: Vec<KnownKey> = vec![];
    let self_keys = SelfTrustSet::new("self", [[42u8; 32], [99u8; 32]]);
    let recipients = vec![TrustIdentity::new("self", KID1, [99u8; 32])];

    let needs =
        judge_recipients_trust(&recipients, &KnownKeyCache::new(&known), &self_keys).unwrap();
    assert!(needs.is_empty());
}

#[test]
fn test_judge_recipients_trust_self_trust_set_skips_only_self_keys() {
    let known: Vec<KnownKey> = vec![];
    let self_keys = SelfTrustSet::new("self", [[42u8; 32], [99u8; 32]]);
    let recipients = vec![
        TrustIdentity::new("self", KID1, [99u8; 32]),
        TrustIdentity::new("other", KID2, [7u8; 32]),
    ];

    let needs =
        judge_recipients_trust(&recipients, &KnownKeyCache::new(&known), &self_keys).unwrap();

    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].member_handle(), "other");
}

// === Self-trust backed by the local keystore ===

/// A local key of this member and the identity a document would name it by.
fn local_self_key() -> (TempDir, KeystoreAccess, TrustIdentity) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .remove(0);
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    let identity = TrustIdentity::from_public_key(&public_key).unwrap();
    let keystore = KeystoreAccess::open(keystore_root).unwrap();

    (temp_dir, keystore, identity)
}

fn self_trust_set_over(keystore: KeystoreAccess) -> SelfTrustSet {
    SelfTrustSet::try_new_with_keystore(ALICE_MEMBER_HANDLE, NO_LISTED_KEYS, keystore).unwrap()
}

/// A key the local keystore holds for this member is the operator's own, so it
/// is recognised without having been listed in the set.
#[test]
fn test_self_trust_set_recognises_a_key_held_in_the_local_keystore() {
    let (_temp_dir, keystore, identity) = local_self_key();
    let self_keys = self_trust_set_over(keystore);

    assert!(self_keys.contains_identity(&identity).unwrap());
}

/// A key the local keystore does not hold belongs to trust review like any
/// other key of another member.
#[test]
fn test_self_trust_set_leaves_a_key_the_keystore_does_not_hold_for_review() {
    let (_temp_dir, keystore, _identity) = local_self_key();
    let self_keys = self_trust_set_over(keystore);
    let absent = TrustIdentity::new(ALICE_MEMBER_HANDLE, KID2, [7u8; 32]);

    assert!(!self_keys.contains_identity(&absent).unwrap());
}

/// A stored key naming a member other than the directory it sits in is local
/// state contradicting itself, which is reported rather than read as a key
/// belonging to somebody else.
#[test]
fn test_self_trust_set_reports_a_stored_key_naming_another_member() {
    let (temp_dir, keystore, identity) = local_self_key();
    let keystore_root = temp_dir.path().join("keys");
    let mut tampered =
        load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, identity.kid()).unwrap();
    tampered.protected.subject_handle = "mallory@example.com".to_string();
    std::fs::write(
        keystore_root
            .join(ALICE_MEMBER_HANDLE)
            .join(identity.kid())
            .join("public.json"),
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let self_keys = self_trust_set_over(keystore);

    let error = self_keys.contains_identity(&identity).unwrap_err();

    assert!(
        error.to_string().contains("mallory@example.com"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_trust_identity_reads_the_canonical_kid_a_public_key_carries() {
    let public_key: PublicKey =
        serde_json::from_str(&minimal_public_key_json(KID1, ALICE_MEMBER_HANDLE)).unwrap();

    let identity = TrustIdentity::from_public_key(&public_key)
        .expect("a stored public key names its key in canonical form");

    assert_eq!(identity.kid(), KID1);
}

/// The key id a judgment is made about is the one the stored document names.
/// A display form is refused rather than normalized, which would judge a key
/// statement under an id its own bytes never carried.
#[test]
fn test_trust_identity_rejects_a_display_form_kid_in_a_public_key() {
    let public_key: PublicKey = serde_json::from_str(&minimal_public_key_json(
        KID1_DISPLAY_FORM,
        ALICE_MEMBER_HANDLE,
    ))
    .unwrap();

    let error = TrustIdentity::from_public_key(&public_key)
        .expect_err("a stored public key must carry a canonical kid");

    assert!(
        error.format_user_message().contains("canonical"),
        "got: {}",
        error.format_user_message()
    );
}
