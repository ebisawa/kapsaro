// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for kv-enc CEK derivation.

use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use secretenv_core::cli_api::test_support::operations::envelope::cek::derive_cek;
use secretenv_core::cli_api::test_support::operations::envelope::key_schedule::{
    FileKeySchedule, KvKeySchedule,
};
use secretenv_core::cli_api::test_support::primitives::types::keys::MasterKey;
use uuid::Uuid;

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
    let mk_obj = MasterKey::new([0u8; 32]);
    let sid = test_sid();
    let nonce = test_nonce(0);

    let cek = derive_cek(&mk_obj, &sid, test_key(), &nonce, false).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid, test_key(), &nonce, false).unwrap();

    assert_eq!(cek.as_bytes().len(), 32);
    assert_eq!(cek.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_nonce() {
    let mk_obj = MasterKey::new([0u8; 32]);
    let sid = test_sid();

    let cek1 = derive_cek(&mk_obj, &sid, test_key(), &test_nonce(0), false).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid, test_key(), &test_nonce(1), false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_mk() {
    let sid = test_sid();
    let nonce = test_nonce(0);

    let cek1 = derive_cek(&MasterKey::new([0u8; 32]), &sid, test_key(), &nonce, false).unwrap();
    let cek2 = derive_cek(&MasterKey::new([1u8; 32]), &sid, test_key(), &nonce, false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_sid() {
    let mk_obj = MasterKey::new([0u8; 32]);
    let nonce = test_nonce(0);
    let sid1 = test_sid();
    let sid2 = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

    let cek1 = derive_cek(&mk_obj, &sid1, test_key(), &nonce, false).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid2, test_key(), &nonce, false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_key() {
    let mk_obj = MasterKey::new([0u8; 32]);
    let sid = test_sid();
    let nonce = test_nonce(0);

    let cek1 = derive_cek(&mk_obj, &sid, "DATABASE_URL", &nonce, false).unwrap();
    let cek2 = derive_cek(&mk_obj, &sid, "API_KEY", &nonce, false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_kv_schedule_separates_cek_and_mac_key() {
    let mk_obj = MasterKey::new([0u8; 32]);
    let sid = test_sid();
    let nonce = test_nonce(0);
    let schedule = KvKeySchedule::extract(&mk_obj, &sid).unwrap();

    let cek = schedule.derive_cek(test_key(), &nonce).unwrap();
    let mac_key = schedule.derive_mac_key().unwrap();

    assert_ne!(cek.as_bytes(), mac_key.as_bytes());
}

#[test]
fn test_file_schedule_separates_content_and_mac_key() {
    let mk_obj = MasterKey::new([0u8; 32]);
    let sid = test_sid();
    let schedule = FileKeySchedule::extract(&mk_obj, &sid).unwrap();

    let content_key = schedule.derive_content_key().unwrap();
    let mac_key = schedule.derive_mac_key().unwrap();

    assert_ne!(content_key.as_bytes(), mac_key.as_bytes());
}
