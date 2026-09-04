// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/decrypt/unwrap error paths
//!
//! Tests error cases and edge cases in decrypt/unwrap operations.
//! The happy path is covered by feature_decrypt_file_test.rs; this file focuses on
//! error paths such as a wrap set with no entry for the local key, empty entries,
//! and a wrap entry whose recipient handle contradicts the selected key.

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::decode_kem_secret_key;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::crypto::SigningContext;
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::envelope::binding::build_file_wrap_info;
use crate::feature::envelope::unwrap::{
    unwrap_master_key, unwrap_master_key_for_file_with_context,
};
use crate::feature::envelope::wrap::build_wrap_item_for_file;
use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::feature::kv::decrypt::decrypt_kv_document_with_context;
use crate::feature::kv::encrypt::encrypt_kv_map_with_wrap_mutation;
use crate::feature::verify::file::verify_file_document;
use crate::feature::verify::kv::signature::verify_kv_document;
use crate::format::kv::document::parse_kv_document;
use crate::format::kv::dotenv::parse_dotenv;
use crate::format::token::TokenCodec;
use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::model::file_enc::FileEncDocument;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::public_key::PublicKey;
use crate::test_support::storage::keystore::storage::{
    list_kids, load_private_key, load_public_key,
};
use crate::test_utils::keygen_helpers::{
    build_verified_private_key, build_verified_recipient_key, build_verified_recipient_keys,
};
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A member handle no local key belongs to.
const FOREIGN_MEMBER_HANDLE: &str = "different@example.com";

// ============================================================================
// Helper Functions
// ============================================================================

/// The local member a test encrypts as and decrypts as.
///
/// The TempDir must be kept alive for the duration of the test to prevent premature
/// cleanup of keystore and workspace files.
struct LocalMember {
    _temp_dir: TempDir,
    key_ctx: CryptoContext,
    public_key: PublicKey,
}

fn setup_local_member() -> LocalMember {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    build_local_member(temp_dir, key_ctx)
}

/// The same local member, with the key id pinned the way `--key` pins it.
///
/// Pinning makes the wrap lookup start from a key id instead of from the
/// entries addressed to this member, which is the path the recipient-handle
/// re-check guards.
fn setup_local_member_with_pinned_kid() -> LocalMember {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let kid = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None)
        .kid()
        .to_string();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&kid));
    build_local_member(temp_dir, key_ctx)
}

fn build_local_member(temp_dir: TempDir, key_ctx: CryptoContext) -> LocalMember {
    let public_key = load_public_key(
        &temp_dir.path().join("keys"),
        ALICE_MEMBER_HANDLE,
        key_ctx.kid(),
    )
    .unwrap();

    LocalMember {
        _temp_dir: temp_dir,
        key_ctx,
        public_key,
    }
}

fn signing_context(member: &LocalMember) -> SigningContext<'_> {
    SigningContext {
        signing_key: member.key_ctx.signing_key(),
        signer_kid: member.key_ctx.kid(),
        signer_pub: member.public_key.clone(),
    }
}

fn encrypt_file_for(
    member: &LocalMember,
    content: &[u8],
    recipients: &[PublicKey],
) -> FileEncDocument {
    let recipient_handles: Vec<String> = recipients
        .iter()
        .map(|key| key.protected.subject_handle.clone())
        .collect();

    encrypt_file_document(
        content,
        &recipient_handles,
        &build_verified_recipient_keys(recipients),
        &signing_context(member),
    )
    .unwrap()
}

fn encrypt_kv_for(
    member: &LocalMember,
    dotenv_content: &str,
    recipients: &[PublicKey],
) -> KvEncDocument {
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &parse_dotenv(dotenv_content).unwrap(),
        &build_verified_recipient_keys(recipients),
        &signing_context(member),
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();

    parse_kv_document(&encrypted).unwrap()
}

/// A public key naming another member while carrying the local key's kid and KEM key.
///
/// Encrypting to it yields a wrap entry the local key can open but that names a
/// different recipient. The entry is part of the signed document and is covered by the
/// key-possession MAC like any other, so only the recipient handle re-check separates
/// the local key from a wrap addressed to someone else.
fn foreign_recipient_sharing_local_key(local_public_key: &PublicKey) -> PublicKey {
    let mut foreign = local_public_key.clone();
    foreign.protected.subject_handle = FOREIGN_MEMBER_HANDLE.to_string();
    foreign
}

/// Take the error out of a decryption that must fail.
///
/// `DecryptionResult` carries key material and has no `Debug`, so `unwrap_err` is
/// not available on a decryption result.
fn expect_decryption_error<T>(result: crate::Result<T>) -> crate::Error {
    match result {
        Ok(_) => panic!("decryption should have failed"),
        Err(error) => error,
    }
}

fn assert_reports_foreign_recipient_handle(error: crate::Error) {
    let message = error.to_string();
    assert!(
        message.contains("does not match member_handle"),
        "Error should mention rh mismatch, got: {}",
        message
    );
    assert!(
        message.contains(FOREIGN_MEMBER_HANDLE),
        "Error should name the wrap entry's recipient handle '{}', got: {}",
        FOREIGN_MEMBER_HANDLE,
        message
    );
}

// ============================================================================
// Test: wrap selection by kid (tested indirectly through public APIs)
// ============================================================================

/// Test that decryption succeeds with the key the context selects.
#[test]
fn test_decrypt_file_selects_wrap_by_kid() {
    let member = setup_local_member();
    let doc = encrypt_file_for(
        &member,
        b"test content",
        std::slice::from_ref(&member.public_key),
    );
    let verified_doc = verify_file_document(&doc).unwrap();

    let result =
        decrypt_file_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &member.key_ctx)
            .unwrap();

    assert_eq!(result.value.as_ref() as &[u8], b"test content");
    assert_eq!(result.key_info.kid, member.key_ctx.kid());
}

/// Test that a member handle none of the wrap entries name produces an error
/// containing "No wrap found".
#[test]
fn test_decrypt_file_reports_missing_wrap_for_member() {
    let member = setup_local_member();
    let doc = encrypt_file_for(
        &member,
        b"test content",
        std::slice::from_ref(&member.public_key),
    );
    let verified_doc = verify_file_document(&doc).unwrap();

    let error = expect_decryption_error(decrypt_file_document_with_context(
        &verified_doc,
        FOREIGN_MEMBER_HANDLE,
        &member.key_ctx,
    ));

    let message = error.to_string();
    assert!(
        message.contains("No wrap found"),
        "Error should mention 'No wrap found', got: {}",
        message
    );
}

/// Test that file decryption rejects a wrap entry whose recipient handle contradicts
/// the key the context selected, even though the entry carries that key's kid.
#[test]
fn test_decrypt_file_rejects_recipient_handle_mismatch() {
    let member = setup_local_member_with_pinned_kid();
    let doc = encrypt_file_for(
        &member,
        b"recipient handle mismatch test",
        &[foreign_recipient_sharing_local_key(&member.public_key)],
    );
    let verified_doc = verify_file_document(&doc).unwrap();

    let error = expect_decryption_error(decrypt_file_document_with_context(
        &verified_doc,
        ALICE_MEMBER_HANDLE,
        &member.key_ctx,
    ));

    assert_reports_foreign_recipient_handle(error);
}

/// Test that kv decryption rejects the same contradiction as the file path.
#[test]
fn test_decrypt_kv_document_rejects_recipient_handle_mismatch() {
    let member = setup_local_member_with_pinned_kid();
    let doc = encrypt_kv_for(
        &member,
        "SECRET_KEY=my-secret-value\n",
        &[foreign_recipient_sharing_local_key(&member.public_key)],
    );
    let verified_doc = verify_kv_document(&doc).unwrap();

    let error = expect_decryption_error(decrypt_kv_document_with_context(
        &verified_doc,
        ALICE_MEMBER_HANDLE,
        &member.key_ctx,
    ));

    assert_reports_foreign_recipient_handle(error);
}

/// A key id may appear on more than one wrap entry, so the entry this member's
/// own key opens is found by key id and recipient handle together rather than
/// by key id alone.
///
/// The entry naming somebody else is listed first here, which is what a lookup
/// on the key id alone would land on.
#[test]
fn test_decrypt_file_selects_the_entry_addressed_to_the_member() {
    let member = setup_local_member();
    let doc = encrypt_file_for(
        &member,
        b"shared kid selection test",
        &[
            foreign_recipient_sharing_local_key(&member.public_key),
            member.public_key.clone(),
        ],
    );
    let verified_doc = verify_file_document(&doc).unwrap();

    let result =
        decrypt_file_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &member.key_ctx)
            .unwrap();

    assert_eq!(result.value.as_ref() as &[u8], b"shared kid selection test");
}

/// Test that kv decryption selects the same entry as the file path.
#[test]
fn test_decrypt_kv_document_selects_the_entry_addressed_to_the_member() {
    let member = setup_local_member();
    let doc = encrypt_kv_for(
        &member,
        "SECRET_KEY=my-secret-value\n",
        &[
            foreign_recipient_sharing_local_key(&member.public_key),
            member.public_key.clone(),
        ],
    );
    let verified_doc = verify_kv_document(&doc).unwrap();

    let decrypted =
        decrypt_kv_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &member.key_ctx)
            .unwrap();

    let value = decrypted
        .value
        .get("SECRET_KEY")
        .expect("SECRET_KEY should exist in decrypted map");
    assert_eq!(
        String::from_utf8(value.to_vec()).unwrap(),
        "my-secret-value"
    );
}

// ============================================================================
// Test: decrypt_kv_entries edge cases (tested through decrypt_kv_document_with_context)
// ============================================================================

/// Test that encrypting an empty KV map produces an empty decrypted map.
#[test]
fn test_decrypt_kv_entries_empty() {
    let member = setup_local_member();
    let doc = encrypt_kv_for(&member, "", std::slice::from_ref(&member.public_key));
    let verified_doc = verify_kv_document(&doc).unwrap();

    let decrypted =
        decrypt_kv_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &member.key_ctx)
            .unwrap();

    assert!(
        decrypted.value.is_empty(),
        "Decrypting empty entries should produce empty map"
    );
}

/// Test that multiple KV entries are all decrypted correctly.
#[test]
fn test_decrypt_kv_entries_multiple() {
    let member = setup_local_member();
    let dotenv = "DB_HOST=localhost\nDB_PORT=5432\nDB_USER=admin\nDB_PASS=secret\n";
    let doc = encrypt_kv_for(&member, dotenv, std::slice::from_ref(&member.public_key));
    let verified_doc = verify_kv_document(&doc).unwrap();

    let decrypted =
        decrypt_kv_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &member.key_ctx)
            .unwrap();

    assert_eq!(decrypted.value.len(), 4, "Should have 4 decrypted entries");

    let expected = [
        ("DB_HOST", "localhost"),
        ("DB_PORT", "5432"),
        ("DB_USER", "admin"),
        ("DB_PASS", "secret"),
    ];

    for (key, expected_value) in &expected {
        let value = decrypted
            .value
            .get(*key)
            .unwrap_or_else(|| panic!("{} should exist in decrypted map", key));
        assert_eq!(
            String::from_utf8(value.to_vec()).unwrap(),
            *expected_value,
            "Value for {} should match",
            key
        );
    }
}

// ============================================================================
// Tests merged from services_enc_unwrap_test.rs
// ============================================================================

fn build_test_master_key() -> MasterKey {
    let key_bytes = [1u8; 32];
    MasterKey::from_zeroizing(Zeroizing::new(key_bytes))
}

#[test]
fn test_unwrap_master_key_for_file() {
    let member = setup_local_member();
    let doc = encrypt_file_for(
        &member,
        b"Hello, World!",
        std::slice::from_ref(&member.public_key),
    );
    let verified = verify_file_document(&doc).unwrap();

    let unwrapped =
        unwrap_master_key_for_file_with_context(&verified, ALICE_MEMBER_HANDLE, &member.key_ctx)
            .unwrap();

    assert_eq!(unwrapped.value.as_bytes().len(), 32);
    assert_eq!(unwrapped.key_info.kid, member.key_ctx.kid());
}

#[test]
fn test_unwrap_master_key_from_wrap_item() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();
    let encrypted_private_key = load_private_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Decrypt private key first (we'll need it for unwrap)
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen", None)),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));
    let private_key_plaintext =
        decrypt_private_key(&encrypted_private_key, backend.as_ref(), &ssh_pub).unwrap();

    let sid = Uuid::new_v4();
    let master_key = build_test_master_key();

    // Extract kid from public key for kids list
    // Create wrap item (wrap in Attested for API)
    let attested_pubkey = build_verified_recipient_key(public_key.clone());
    let wrap_item = build_wrap_item_for_file(&attested_pubkey, &sid, &master_key).unwrap();

    // Unwrap master key using the same private key that matches the public key used to create wrap
    // Note: build_wrap_item_for_file uses hpke_info::file, so we need to use unwrap_master_key_base
    // with hpke_info::file instead of unwrap_master_key_from_wrap_item (which uses hpke_info::kv_file)
    let decrypted_key = build_verified_private_key(
        &private_key_plaintext,
        ALICE_MEMBER_HANDLE,
        &public_key.protected.kid,
        "SHA256:test",
    );
    let kem_secret_key = decode_kem_secret_key(&decrypted_key).unwrap();
    let wrap_set =
        crate::feature::envelope::wrap_set::WrapSet::parse(&[wrap_item], "Document").unwrap();
    let parsed_wrap_item = wrap_set
        .find_by_kid_for_member(
            &Kid::new(public_key.protected.kid.clone()).unwrap(),
            &MemberHandle::new(ALICE_MEMBER_HANDLE).unwrap(),
        )
        .unwrap();
    let unwrapped_key = unwrap_master_key(
        parsed_wrap_item,
        &sid,
        &kem_secret_key,
        build_file_wrap_info,
        "test_unwrap_master_key_from_wrap_item",
    )
    .unwrap();

    // Verify unwrapped key matches original
    assert_eq!(unwrapped_key.as_bytes(), master_key.as_bytes());
}

/// Test defence-in-depth: HPKE AAD binding (aad=info) prevents unwrap with wrong AAD
#[test]
fn test_hpke_aad_binding_defence_in_depth() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();
    let encrypted_private_key = load_private_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Decrypt private key
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen", None)),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));
    let private_key_plaintext =
        decrypt_private_key(&encrypted_private_key, backend.as_ref(), &ssh_pub).unwrap();

    let sid = Uuid::new_v4();
    let master_key = build_test_master_key();

    // Create wrap item (uses aad=info) - wrap in Attested for API
    let attested_pubkey = build_verified_recipient_key(public_key.clone());
    let wrap_item = build_wrap_item_for_file(&attested_pubkey, &sid, &master_key).unwrap();

    // Try to unwrap with empty AAD. This demonstrates that aad=info binding is enforced.
    let decrypted_key = build_verified_private_key(
        &private_key_plaintext,
        ALICE_MEMBER_HANDLE,
        &public_key.protected.kid,
        "SHA256:test",
    );
    let kem_secret_key = decode_kem_secret_key(&decrypted_key).unwrap();

    // Attempt unwrap with wrong AAD (empty instead of info)
    // This should fail because the wrap was created with aad=info
    use crate::crypto::kem::open_base;
    use crate::crypto::types::data::{Aad, Ciphertext, Enc};
    use crate::format::codec::base64_public::decode_base64url_nopad;

    let enc_bytes = decode_base64url_nopad(&wrap_item.enc, "enc").unwrap();
    let enc = Enc::from(enc_bytes);
    let ct_bytes = decode_base64url_nopad(&wrap_item.ct, "ct").unwrap();
    let ct = Ciphertext::from(ct_bytes);

    let info = build_file_wrap_info(&sid, kid).unwrap();
    let wrong_aad = Aad::new(Vec::new()); // Wrong AAD (empty instead of info)

    let result = open_base(&kem_secret_key, &enc, &info, &wrong_aad, &ct);

    // Should fail because AAD doesn't match (defence-in-depth)
    assert!(
        result.is_err(),
        "Unwrap with wrong AAD (empty instead of info) should fail"
    );
}
