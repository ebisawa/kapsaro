// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the kv-enc and file-enc key schedules.

use crate::crypto::types::keys::{Cek, MasterKey};
use crate::feature::envelope::key_schedule::{FileKeySchedule, KvKeySchedule};
use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::Result;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Derive one entry CEK the way an encryption run does.
///
/// The schedule is extracted per call so each case states the whole derivation
/// it depends on, rather than sharing one extraction across unrelated cases.
fn derive_cek(mk: &MasterKey, sid: &Uuid, key: &str, nonce_b64: &str) -> Result<Cek> {
    KvKeySchedule::extract(mk, sid)?.derive_cek(key, nonce_b64)
}

fn test_sid() -> Uuid {
    Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
}

fn test_key() -> &'static str {
    "DATABASE_URL"
}

fn test_nonce(byte: u8) -> String {
    encode_base64url_nopad(&[byte; 24])
}

#[test]
fn test_derive_cek() {
    let mk_obj = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let sid = test_sid();
    let nonce = test_nonce(0);

    let cek = derive_cek(&mk_obj, &sid, test_key(), &nonce).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid, test_key(), &nonce).unwrap();

    assert_eq!(cek.as_bytes().len(), 32);
    assert_eq!(cek.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_nonce() {
    let mk_obj = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let sid = test_sid();

    let cek1 = derive_cek(&mk_obj, &sid, test_key(), &test_nonce(0)).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid, test_key(), &test_nonce(1)).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_mk() {
    let sid = test_sid();
    let nonce = test_nonce(0);

    let mk1 = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let mk2 = MasterKey::from_zeroizing(Zeroizing::new([1u8; 32]));

    let cek1 = derive_cek(&mk1, &sid, test_key(), &nonce).unwrap();
    let cek2 = derive_cek(&mk2, &sid, test_key(), &nonce).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_sid() {
    let mk_obj = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let nonce = test_nonce(0);
    let sid1 = test_sid();
    let sid2 = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

    let cek1 = derive_cek(&mk_obj, &sid1, test_key(), &nonce).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid2, test_key(), &nonce).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_key() {
    let mk_obj = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let sid = test_sid();
    let nonce = test_nonce(0);

    let cek1 = derive_cek(&mk_obj, &sid, "DATABASE_URL", &nonce).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid, "API_KEY", &nonce).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_kv_schedule_separates_cek_and_mac_key() {
    let mk_obj = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let sid = test_sid();
    let nonce = test_nonce(0);
    let schedule = KvKeySchedule::extract(&mk_obj, &sid).unwrap();

    let cek = schedule.derive_cek(test_key(), &nonce).unwrap();
    let mac_key = schedule.derive_mac_key().unwrap();

    assert_ne!(cek.as_bytes(), mac_key.as_bytes());
}

/// The two protocols must not derive the same key from the same artifact.
///
/// Both schedules are extracted from one master key and one sid, so only the
/// protocol labels in their salt and info separate them. A key reused across
/// the two would let a kv-enc artifact and a file-enc artifact authenticate
/// each other's bytes.
#[test]
fn test_file_and_kv_schedules_derive_separate_keys_for_one_artifact() {
    let mk_obj = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let sid = test_sid();

    let file_mac_key = FileKeySchedule::extract(&mk_obj, &sid)
        .unwrap()
        .derive_mac_key()
        .unwrap();
    let kv_mac_key = KvKeySchedule::extract(&mk_obj, &sid)
        .unwrap()
        .derive_mac_key()
        .unwrap();

    assert_ne!(file_mac_key.as_bytes(), kv_mac_key.as_bytes());
}

#[test]
fn test_file_schedule_separates_content_and_mac_key() {
    let mk_obj = MasterKey::from_zeroizing(Zeroizing::new([0u8; 32]));
    let sid = test_sid();
    let schedule = FileKeySchedule::extract(&mk_obj, &sid).unwrap();

    let content_key = schedule.derive_content_key().unwrap();
    let mac_key = schedule.derive_mac_key().unwrap();

    assert_ne!(content_key.as_bytes(), mac_key.as_bytes());
}
