// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/services/enc/v3/wrap module
//!
//! Tests for wrap item creation.

use crate::keygen_helpers::build_verified_recipient_key;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{generate_temp_ssh_keypair_in_dir, keygen_test};
use secretenv::crypto::types::keys::MasterKey;
use secretenv::feature::envelope::wrap::WrapFormat;
use secretenv::feature::envelope::wrap::{
    build_wrap_item_for_file, build_wrap_item_for_kv, build_wraps_for_recipients,
};
use secretenv::support::limits::MAX_WRAP_ITEMS;
use tempfile::TempDir;
use uuid::Uuid;

fn build_test_master_key() -> MasterKey {
    let key_bytes = [1u8; 32];
    MasterKey::new(key_bytes)
}

#[test]
fn test_build_wrap_item_for_file() {
    let ssh_temp = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_private_key, public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let sid = Uuid::new_v4();
    let master_key = build_test_master_key();
    let kid = public_key.protected.kid.clone();
    let attested_pubkey = build_verified_recipient_key(public_key);

    let wrap_item = build_wrap_item_for_file(&attested_pubkey, &sid, &master_key, false).unwrap();

    assert_eq!(wrap_item.recipient_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(wrap_item.kid, kid);
    assert!(!wrap_item.enc.is_empty());
    assert!(!wrap_item.ct.is_empty());
}

#[test]
fn test_build_wrap_item_for_kv() {
    let ssh_temp = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_private_key, public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let sid = Uuid::new_v4();
    let master_key = build_test_master_key();
    let kid = public_key.protected.kid.clone();
    let attested_pubkey = build_verified_recipient_key(public_key);

    let wrap_item = build_wrap_item_for_kv(&sid, &attested_pubkey, &master_key, false).unwrap();

    assert_eq!(wrap_item.recipient_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(wrap_item.kid, kid);
    assert!(!wrap_item.enc.is_empty());
    assert!(!wrap_item.ct.is_empty());
}

#[test]
fn test_build_wraps_for_recipients_file() {
    let ssh_temp = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_private_key1, public_key1) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let (_private_key2, public_key2) =
        keygen_test("bob@example.com", &ssh_priv, &ssh_pub_content).unwrap();
    let sid = Uuid::new_v4();
    let attested_members = vec![
        build_verified_recipient_key(public_key1.clone()),
        build_verified_recipient_key(public_key2.clone()),
    ];
    let master_key = build_test_master_key();

    let wrap_items = build_wraps_for_recipients(
        &attested_members,
        &sid,
        &master_key,
        WrapFormat::File,
        false,
    )
    .unwrap();

    assert_eq!(wrap_items.len(), 2);
    assert_eq!(wrap_items[0].recipient_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(wrap_items[1].recipient_handle, "bob@example.com");
}

#[test]
fn test_build_wraps_for_recipients_kv() {
    let ssh_temp = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_private_key1, public_key1) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let (_private_key2, public_key2) =
        keygen_test("bob@example.com", &ssh_priv, &ssh_pub_content).unwrap();
    let sid = Uuid::new_v4();
    let attested_members = vec![
        build_verified_recipient_key(public_key1.clone()),
        build_verified_recipient_key(public_key2.clone()),
    ];
    let master_key = build_test_master_key();

    let wrap_items =
        build_wraps_for_recipients(&attested_members, &sid, &master_key, WrapFormat::Kv, false)
            .unwrap();

    assert_eq!(wrap_items.len(), 2);
    assert_eq!(wrap_items[0].recipient_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(wrap_items[1].recipient_handle, "bob@example.com");
}

#[test]
fn test_build_wraps_for_recipients_rejects_count_over_limit() {
    let ssh_temp = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_private_key, public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let sid = Uuid::new_v4();
    let attested_member = build_verified_recipient_key(public_key);
    let attested_members = vec![attested_member; MAX_WRAP_ITEMS + 1];
    let master_key = build_test_master_key();

    let result =
        build_wraps_for_recipients(&attested_members, &sid, &master_key, WrapFormat::Kv, false);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("wrap count"));
}
