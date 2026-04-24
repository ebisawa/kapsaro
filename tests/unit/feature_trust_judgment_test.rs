// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust judgment logic

use secretenv::feature::trust::judgment::{
    judge_recipients_trust, judge_signer_trust, ActiveMemberSnapshot, KnownKeyCache, SelfTrustSet,
    TrustIdentity, TrustJudgment,
};
use secretenv::model::identity::{Kid, MemberId};
use secretenv::model::public_key::PublicKey;
use secretenv::model::trust_store::{KnownKey, KnownKeyApprovalVia};
use std::collections::BTreeMap;

const KID1: &str = "KAD1AAAA1111BBBB2222CCCC3333DDDD";
const KID2: &str = "KBD2AAAA1111BBBB2222CCCC3333DDDD";

fn member_id(value: &str) -> MemberId {
    MemberId::try_from(value).unwrap()
}

fn kid_value(value: &str) -> Kid {
    Kid::try_from(value).unwrap()
}

fn build_known_key(kid: &str, member_id: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        member_id: member_id.to_string(),
        approved_at: "2026-03-29T12:40:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn build_active_members(entries: &[(&str, &str)]) -> BTreeMap<String, PublicKey> {
    let mut map = BTreeMap::new();
    for (kid, member_id) in entries {
        let pk: PublicKey = serde_json::from_str(&minimal_public_key_json(kid, member_id)).unwrap();
        map.insert(kid.to_string(), pk);
    }
    map
}

fn minimal_public_key_json(kid: &str, member_id: &str) -> String {
    format!(
        r#"{{
        "protected": {{
            "format": "secretenv.public.key@4",
            "member_id": "{}",
            "kid": "{}",
            "identity": {{
                "keys": {{
                    "kem": {{ "kty": "OKP", "crv": "X25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }},
                    "sig": {{ "kty": "OKP", "crv": "Ed25519", "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }}
                }},
                "attestation": {{
                    "method": "ssh",
                    "pub": "ssh-ed25519 test",
                    "sig": "test"
                }}
            }},
            "expires_at": "2030-01-01T00:00:00Z"
        }},
        "signature": "test_sig"
    }}"#,
        member_id, kid
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
            member_id: member_id("bob"),
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
            member_id: member_id("bob"),
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
            member_id: member_id("other"),
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

// === P2 regression: kid cached with different member_id (spec §9.4) ===

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
            member_id: member_id("bob"),
            kid: kid_value(kid),
            known_member_id: member_id("alice"),
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
fn test_judge_signer_trust_member_id_mismatch_is_not_current_member() {
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
            member_id: member_id("bob@example.com"),
            kid: kid_value(kid),
            active_member_id: member_id("alice@example.com"),
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
    assert_eq!(needs[0].member_id(), "bob");
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
    assert_eq!(needs[0].member_id(), "bob");
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
    assert_eq!(needs[0].member_id(), "other");
}
