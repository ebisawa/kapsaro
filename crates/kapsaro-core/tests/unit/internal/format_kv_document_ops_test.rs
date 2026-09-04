// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for kv-enc v1 encryption/decryption operations.

use crate::feature::context::crypto::SigningContext;
use crate::feature::kv::decrypt::decrypt_kv_document_with_context;
use crate::feature::kv::encrypt::encrypt_kv_map_with_wrap_mutation;
use crate::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot,
    KvWriteContext,
};
use crate::feature::kv::types::KvInputEntry;
use crate::format::content::KvEncContent;
use crate::format::kv::document::parse_kv_document;
use crate::format::kv::dotenv::parse_dotenv;
use crate::format::schema::document::{parse_kv_head_token_with_source, parse_kv_wrap_token};
use crate::format::token::TokenCodec;
use crate::io::workspace::members::test_support::{list_active_member_handles, load_member_files};
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::public_key::PublicKey;
use crate::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use crate::test_utils::keygen_helpers::{build_test_private_key, build_verified_recipient_keys};
use crate::test_utils::{generate_temp_ssh_keypair_in_dir, keygen_test};
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE};
use ed25519_dalek::SigningKey;

fn ensure_secret_home() -> tempfile::TempDir {
    let temp = tempfile::TempDir::new().unwrap();
    crate::test_utils::ensure_local_state_dir(temp.path());
    temp
}

/// Generate Ed25519 signing key from seed for tests
fn generate_ed25519_keypair(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

/// The key material one member needs to reach a keystore-backed crypto context.
struct TestMemberKeys<'a> {
    member_handle: &'a str,
    private_key: &'a crate::model::private_key::PrivateKeyPlaintext,
    public_key: &'a PublicKey,
    ssh_private_key_path: &'a std::path::Path,
    ssh_public_key: &'a str,
}

/// Helper function to decrypt kv-enc content for tests (creates Verified wrapper)
///
/// The member's key pair is installed into a throwaway keystore first, so decryption
/// selects the local key the same way the commands do.
fn decrypt_kv_document_for_test(
    encrypted: &str,
    signer_kid: &str,
    member: TestMemberKeys<'_>,
) -> std::collections::HashMap<String, String> {
    let home = ensure_secret_home();
    let key_ctx = setup_crypto_ctx_for_test(
        member.member_handle,
        &member.public_key.protected.kid,
        &home.path().join("keys"),
        member.private_key,
        member.public_key,
        member.ssh_private_key_path,
        member.ssh_public_key,
    );

    let doc = parse_kv_document(encrypted).unwrap();
    let proof = SignatureVerificationProof::new_with_signer_public_key(
        member.member_handle.to_string(),
        signer_kid.to_string(),
        member.public_key.clone(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    let verified_doc = VerifiedKvEncDocument::new(doc, proof);
    // Convert Zeroizing<Vec<u8>> to String at the boundary
    decrypt_kv_document_with_context(&verified_doc, member.member_handle, &key_ctx)
        .unwrap()
        .value
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8(v.to_vec()).unwrap()))
        .collect()
}

fn encrypt_kv_document_for_parse_test(input: &str) -> String {
    let signing_key = generate_ed25519_keypair([2u8; 32]);
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_private, public) = keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let members = vec![public.clone()];
    let verified_members = build_verified_recipient_keys(&members);
    let kv_map = parse_dotenv(input).unwrap();
    encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            signer_pub: public,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap()
}

fn replace_line_key(content: &str, old_key: &str, new_key: &str) -> String {
    content
        .lines()
        .map(|line| {
            if let Some(token) = line.strip_prefix(&format!("{} ", old_key)) {
                format!("{} {}", new_key, token)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn test_encrypt_and_decrypt_kv() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    // Generate test keys
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private1, public1) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let (private2, public2) = keygen_test(BOB_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    // Input dotenv
    let input = "DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n";

    // Encrypt for two recipients
    let members: Vec<PublicKey> = vec![public1.clone(), public2.clone()];
    let verified_members = build_verified_recipient_keys(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub: public1.clone(),
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();

    // Verify structure
    assert!(encrypted.starts_with(":KAPSARO_KV 1\n"));
    assert!(encrypted.contains(":HEAD "));
    assert!(encrypted.contains(":WRAP "));
    assert!(encrypted.contains("DATABASE_URL "));
    assert!(encrypted.contains("API_KEY "));

    // Decrypt with alice's key
    let decrypted_map1 = decrypt_kv_document_for_test(
        &encrypted,
        signer_kid,
        TestMemberKeys {
            member_handle: ALICE_MEMBER_HANDLE,
            private_key: &private1,
            public_key: &public1,
            ssh_private_key_path: &ssh_priv,
            ssh_public_key: &ssh_pub_content,
        },
    );
    assert_eq!(decrypted_map1.len(), 2);
    assert_eq!(
        decrypted_map1.get("API_KEY").map(String::as_str),
        Some("secret123")
    );
    assert_eq!(
        decrypted_map1.get("DATABASE_URL").map(String::as_str),
        Some("postgres://localhost")
    );

    // Decrypt with bob's key
    let decrypted_map2 = decrypt_kv_document_for_test(
        &encrypted,
        signer_kid,
        TestMemberKeys {
            member_handle: BOB_MEMBER_HANDLE,
            private_key: &private2,
            public_key: &public2,
            ssh_private_key_path: &ssh_priv,
            ssh_public_key: &ssh_pub_content,
        },
    );
    assert_eq!(decrypted_map2.len(), 2);
    assert_eq!(
        decrypted_map2.get("API_KEY").map(String::as_str),
        Some("secret123")
    );
    assert_eq!(
        decrypted_map2.get("DATABASE_URL").map(String::as_str),
        Some("postgres://localhost")
    );
}

#[test]
fn test_parse_kv_document_keeps_validated_entries_and_signature() {
    let encrypted = encrypt_kv_document_for_parse_test("A=one\nB=two\n");
    let doc = parse_kv_document(&encrypted).unwrap();

    let keys: Vec<&str> = doc.entries().iter().map(|entry| entry.key()).collect();
    assert_eq!(keys, vec!["A", "B"]);
    assert!(!doc.entries()[0].token().is_empty());
    assert!(!doc.signature().sig.is_empty());
    assert_eq!(doc.signature().kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
}

#[test]
fn test_parse_kv_document_rejects_duplicate_key_before_token_reparse() {
    let encrypted = encrypt_kv_document_for_parse_test("A=one\nB=two\n");
    let duplicated = replace_line_key(&encrypted, "B", "A");

    let err = parse_kv_document(&duplicated).unwrap_err();

    assert!(err.to_string().contains("E_DUPLICATE_KEY"));
}

#[test]
fn test_parse_kv_document_uses_line_key_as_entry_identity() {
    let encrypted = encrypt_kv_document_for_parse_test("A=one\n");
    let renamed = replace_line_key(&encrypted, "A", "B");

    let doc = parse_kv_document(&renamed).unwrap();

    assert_eq!(doc.entries()[0].key(), "B");
}

#[test]
fn test_encrypt_empty_input() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_, public) = keygen_test(TEST_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    let input = "";
    let signer_pub = public.clone();
    let members = vec![public];
    let verified_members = build_verified_recipient_keys(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();

    // Should have header, HEAD line, WRAP line, and SIG line (v3 requires signature)
    assert!(encrypted.starts_with(":KAPSARO_KV 1\n"));
    assert!(encrypted.contains(":HEAD "));
    assert!(encrypted.contains(":WRAP "));
    assert!(encrypted.contains(":SIG "));
    let lines: Vec<&str> = encrypted.lines().collect();
    assert_eq!(lines.len(), 4); // header + HEAD + WRAP + SIG
}

#[test]
fn test_encrypt_with_comments_and_blank_lines() {
    // Note: This test uses dotenv input (plaintext), which allows comments.
    // Comments in dotenv input are filtered out during encryption.
    // kv-enc output format does NOT allow comment lines.
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(TEST_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    let input = r#"# This is a comment
DATABASE_URL=postgres://localhost

# Another comment
API_KEY=secret123
"#;

    let signer_pub = public.clone();
    let members = vec![public];
    let verified_members = build_verified_recipient_keys(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();

    // Comments and blank lines from dotenv input should be filtered out in kv-enc output
    assert!(encrypted.contains("DATABASE_URL "));
    assert!(encrypted.contains("API_KEY "));
    assert!(!encrypted.contains("# This is a comment"));

    // Decrypt
    let decrypted_map = decrypt_kv_document_for_test(
        &encrypted,
        signer_kid,
        TestMemberKeys {
            member_handle: TEST_MEMBER_HANDLE,
            private_key: &private,
            public_key: &members[0],
            ssh_private_key_path: &ssh_priv,
            ssh_public_key: &ssh_pub_content,
        },
    );
    // Should only carry the two KEY=VALUE entries
    assert_eq!(decrypted_map.len(), 2);
    assert_eq!(
        decrypted_map.get("DATABASE_URL").map(String::as_str),
        Some("postgres://localhost")
    );
    assert_eq!(
        decrypted_map.get("API_KEY").map(String::as_str),
        Some("secret123")
    );
}

#[test]
fn test_large_value_in_kv_enc() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(TEST_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    // Create input with a large value
    let large_value = "A".repeat(500);
    let input = format!("LARGE_KEY={}\n", large_value);

    let signer_pub = public.clone();
    let members = vec![public];
    let verified_members = build_verified_recipient_keys(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(&input).unwrap();
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();

    // Decrypt and verify correctness
    let decrypted_map = decrypt_kv_document_for_test(
        &encrypted,
        signer_kid,
        TestMemberKeys {
            member_handle: TEST_MEMBER_HANDLE,
            private_key: &private,
            public_key: &members[0],
            ssh_private_key_path: &ssh_priv,
            ssh_public_key: &ssh_pub_content,
        },
    );
    assert_eq!(decrypted_map.len(), 1);
    assert_eq!(
        decrypted_map.get("LARGE_KEY").map(String::as_str),
        Some(large_value.as_str())
    );
}

#[test]
fn test_wrap_line_with_many_recipients() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    // Create multiple recipients to make WRAP larger
    // Generate all keys first and keep them
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let mut keys = Vec::new();
    for i in 0..10 {
        let email = format!("user{}@example.com", i);
        keys.push(keygen_test(&email, &ssh_priv, &ssh_pub_content).unwrap());
    }

    let members: Vec<PublicKey> = keys.iter().map(|(_, pub_key)| pub_key.clone()).collect();
    let verified_members = build_verified_recipient_keys(&members);
    let (private, user_public_key) = &keys[0]; // Use the first user's key pair

    let input = "KEY=value\n";
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub: members[0].clone(),
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();

    // Find the WRAP line
    let lines: Vec<&str> = encrypted.lines().collect();
    let wrap_line = lines
        .iter()
        .find(|l| l.starts_with(":WRAP "))
        .expect("WRAP line should exist");

    // Extract the token
    wrap_line.strip_prefix(":WRAP ").unwrap();

    // We just verify it can be decrypted successfully
    // Get kid from wrap
    let wrap_line = encrypted
        .lines()
        .find(|l| l.starts_with(":WRAP "))
        .expect("WRAP line should exist");
    let wrap_token = wrap_line.strip_prefix(":WRAP ").unwrap();
    let wrap_data: crate::model::kv_enc::header::KvWrap = parse_kv_wrap_token(wrap_token).unwrap();
    let user_kid = wrap_data
        .wrap
        .iter()
        .find(|w| w.recipient_handle == "user0@example.com")
        .map(|w| w.kid.as_str())
        .expect("Should find wrap for user0@example.com");
    assert_eq!(user_kid, user_public_key.protected.kid);
    let decrypted_map = decrypt_kv_document_for_test(
        &encrypted,
        signer_kid,
        TestMemberKeys {
            member_handle: "user0@example.com",
            private_key: private,
            public_key: user_public_key,
            ssh_private_key_path: &ssh_priv,
            ssh_public_key: &ssh_pub_content,
        },
    );
    assert_eq!(decrypted_map.len(), 1);
    assert_eq!(decrypted_map.get("KEY").map(String::as_str), Some("value"));
}

// ============================================================
// set_kv_entry: reuse tests (sid, created_at and WRAP tokens stay unchanged)
// ============================================================

fn signing_key_from_private(
    private_key: &crate::model::private_key::PrivateKeyPlaintext,
) -> ed25519_dalek::SigningKey {
    use crate::format::codec::base64_public::decode_base64url_nopad_array;
    let sig_d = decode_base64url_nopad_array(&private_key.keys.sig.d, "sig.d").unwrap();
    ed25519_dalek::SigningKey::from_bytes(&sig_d)
}

fn setup_crypto_ctx_for_test(
    member_handle: &str,
    kid: &str,
    keystore_root: &std::path::Path,
    private_key: &crate::model::private_key::PrivateKeyPlaintext,
    public_key: &crate::model::public_key::PublicKey,
    ssh_priv: &std::path::Path,
    ssh_pub_content: &str,
) -> crate::feature::context::crypto::CryptoContext {
    crate::test_utils::ensure_local_state_dir(keystore_root);
    let workspace_path = Some(keystore_root.parent().unwrap().join("workspace"));
    let encrypted_private =
        build_test_private_key(private_key, member_handle, kid, ssh_priv, ssh_pub_content).unwrap();
    let member_dir = keystore_root.join(member_handle);
    crate::test_utils::ensure_local_state_dir(&member_dir);
    let key_dir = keystore_root.join(member_handle).join(kid);
    crate::test_utils::ensure_local_state_dir(&key_dir);
    let private_key_path = key_dir.join("private.json");
    crate::support::fs::atomic::save_json(&private_key_path, &encrypted_private).unwrap();
    crate::test_utils::restrict_local_state_file(&private_key_path);
    crate::test_utils::save_public_key(keystore_root, member_handle, kid, public_key).unwrap();
    let backend = crate::test_utils::ed25519_backend::Ed25519DirectBackend::new(ssh_priv).unwrap();

    crate::feature::context::crypto::load_crypto_context_from_keystore(
        crate::io::keystore::access::KeystoreAccess::open(keystore_root).unwrap(),
        crate::model::identity::MemberHandle::try_from(member_handle).unwrap(),
        Some(kid),
        Box::new(backend),
        ssh_pub_content.to_string(),
        workspace_path,
    )
    .unwrap()
}

fn encrypt_initial_kv_doc(
    member_handle: &str,
    kid: &str,
    keystore_root: &std::path::Path,
    private_key: &crate::model::private_key::PrivateKeyPlaintext,
    public_key: &crate::model::public_key::PublicKey,
    entries: &[(&str, &str)],
) -> String {
    let signing_key = signing_key_from_private(private_key);

    crate::test_utils::save_public_key(keystore_root, member_handle, kid, public_key).unwrap();

    // Create workspace with active member for signature verification
    let workspace_dir = keystore_root.parent().unwrap().join("workspace");
    let members_dir = workspace_dir.join("members/active");
    std::fs::create_dir_all(&members_dir).unwrap();
    std::fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();
    let member_file = members_dir.join(format!("{}.json", member_handle));
    std::fs::write(
        &member_file,
        serde_json::to_string_pretty(public_key).unwrap(),
    )
    .unwrap();

    let verified_members = build_verified_recipient_keys(std::slice::from_ref(public_key));

    let mut kv_map = std::collections::HashMap::new();
    for (k, v) in entries {
        kv_map.insert(k.to_string(), v.to_string());
    }

    encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap()
}

fn kv_entry_token(content: &str, key: &str) -> Option<String> {
    let prefix = format!("{} ", key);
    content
        .lines()
        .find(|l| l.starts_with(&prefix))
        .map(|l| l[prefix.len()..].to_string())
}

fn kv_head_field(content: &str, field: &str) -> String {
    use crate::model::kv_enc::header::KvHeader;
    let token = content
        .lines()
        .find(|l| l.starts_with(":HEAD "))
        .unwrap()
        .strip_prefix(":HEAD ")
        .unwrap();
    let head: KvHeader = parse_kv_head_token_with_source(token, "HEAD token").unwrap();
    match field {
        "sid" => head.sid.to_string(),
        "created_at" => head.created_at,
        "updated_at" => head.updated_at,
        _ => panic!("unknown field: {}", field),
    }
}

fn set_kv_entry(
    existing_content: Option<&KvEncContent>,
    entries: &[(String, String)],
    workspace_root: &std::path::Path,
    ctx: &KvWriteContext<'_>,
) -> kapsaro_core::Result<KvEncContent> {
    let recipients = build_recipient_snapshot(workspace_root)?;
    let entries = entries
        .iter()
        .map(|(key, value)| KvInputEntry::new(key.clone(), value.clone()))
        .collect::<Vec<_>>();
    set_kv_entry_with_recipients(existing_content, &entries, &recipients, ctx)
}

fn unset_kv_entry(
    content: &KvEncContent,
    key: &str,
    ctx: &KvWriteContext<'_>,
) -> kapsaro_core::Result<String> {
    let workspace_root = ctx.key_ctx.workspace_path().ok_or_else(|| {
        kapsaro_core::Error::build_config_error("Workspace is required for kv mutation".to_string())
    })?;
    let recipients = build_recipient_snapshot(workspace_root)?;
    unset_kv_entry_with_recipients(content, key, &recipients, ctx)
}

fn build_recipient_snapshot(
    workspace_root: &std::path::Path,
) -> kapsaro_core::Result<KvRecipientSnapshot> {
    let member_handles = list_active_member_handles(workspace_root)?;
    let public_keys = load_member_files(workspace_root, &member_handles)?;
    let verified_members =
        crate::feature::verify::public_key::verify_recipient_public_keys(&public_keys)?;
    Ok(KvRecipientSnapshot {
        member_handles,
        verified_members,
    })
}

#[test]
fn test_set_existing_file_preserves_sid() {
    let member_handle = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();

    let temp = ensure_secret_home();
    let keystore_root = temp.path().join("keys");

    let initial = encrypt_initial_kv_doc(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        &[("KEY1", "value1")],
    );
    let sid_before = kv_head_field(&initial, "sid");
    let created_at_before = kv_head_field(&initial, "created_at");

    let key_ctx = setup_crypto_ctx_for_test(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        &ssh_priv,
        &ssh_pub_content,
    );
    let ctx = KvWriteContext::new(member_handle, &key_ctx);
    let entries = vec![("KEY2".to_string(), "value2".to_string())];
    let initial_content = KvEncContent::new_unchecked(initial);
    let workspace_dir = temp.path().join("workspace");
    let result = set_kv_entry(Some(&initial_content), &entries, &workspace_dir, &ctx).unwrap();

    assert_eq!(
        sid_before,
        kv_head_field(result.as_str(), "sid"),
        "sid must be preserved"
    );
    assert_eq!(
        created_at_before,
        kv_head_field(result.as_str(), "created_at"),
        "created_at must be preserved"
    );
}

#[test]
fn test_set_existing_file_uses_current_recipients_in_wrap() {
    let member_handle = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();

    let temp = ensure_secret_home();
    let keystore_root = temp.path().join("keys");

    let initial = encrypt_initial_kv_doc(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        &[("KEY1", "value1")],
    );
    let key_ctx = setup_crypto_ctx_for_test(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        &ssh_priv,
        &ssh_pub_content,
    );
    let ctx = KvWriteContext::new(member_handle, &key_ctx);
    let entries = vec![("KEY2".to_string(), "value2".to_string())];
    let initial_content = KvEncContent::new_unchecked(initial);
    let workspace_dir = temp.path().join("workspace");
    let result = set_kv_entry(Some(&initial_content), &entries, &workspace_dir, &ctx).unwrap();

    let wrap = parse_kv_document(result.as_str()).unwrap().wrap;
    let recipients = wrap
        .wrap
        .iter()
        .map(|item| item.recipient_handle.as_str())
        .collect::<Vec<_>>();
    assert_eq!(recipients, vec![member_handle]);
}

#[test]
fn test_set_existing_file_preserves_other_entry_tokens() {
    let member_handle = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();

    let temp = ensure_secret_home();
    let keystore_root = temp.path().join("keys");

    let initial = encrypt_initial_kv_doc(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        &[("KEY1", "value1"), ("KEY2", "value2")],
    );
    let key1_token_before = kv_entry_token(&initial, "KEY1").unwrap();
    let key2_token_before = kv_entry_token(&initial, "KEY2").unwrap();

    let key_ctx = setup_crypto_ctx_for_test(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        &ssh_priv,
        &ssh_pub_content,
    );
    let ctx = KvWriteContext::new(member_handle, &key_ctx);
    let entries = vec![("KEY3".to_string(), "value3".to_string())];
    let initial_content = KvEncContent::new_unchecked(initial);
    let workspace_dir = temp.path().join("workspace");
    let result = set_kv_entry(Some(&initial_content), &entries, &workspace_dir, &ctx).unwrap();

    assert_eq!(
        key1_token_before,
        kv_entry_token(result.as_str(), "KEY1").unwrap(),
        "KEY1 token must be unchanged"
    );
    assert_eq!(
        key2_token_before,
        kv_entry_token(result.as_str(), "KEY2").unwrap(),
        "KEY2 token must be unchanged"
    );
}

// ============================================================
// unset_kv_entry: reuse tests
// ============================================================

/// Shared setup for the unset tests.
fn setup_unset_test_ctx(
    entries: &[(&str, &str)],
) -> (
    String,                                         // initial content
    crate::feature::context::crypto::CryptoContext, // key context
    tempfile::TempDir,                              // must be kept alive
    tempfile::TempDir,                              // SSH temp dir - must be kept alive
) {
    let member_handle = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();
    let temp = ensure_secret_home();
    let keystore_root = temp.path().join("keys");

    let initial = encrypt_initial_kv_doc(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        entries,
    );

    let key_ctx = setup_crypto_ctx_for_test(
        member_handle,
        &kid,
        &keystore_root,
        &private,
        &public,
        &ssh_priv,
        &ssh_pub_content,
    );
    (initial, key_ctx, temp, ssh_temp)
}

#[test]
fn test_unset_preserves_sid_and_created_at() {
    let (initial, key_ctx, _temp, _ssh_temp) =
        setup_unset_test_ctx(&[("KEY1", "value1"), ("KEY2", "value2")]);
    let sid_before = kv_head_field(&initial, "sid");
    let created_at_before = kv_head_field(&initial, "created_at");
    let ctx = KvWriteContext::new("alice@example.com", &key_ctx);

    let initial = KvEncContent::new_unchecked(initial);
    let result = unset_kv_entry(&initial, "KEY1", &ctx).unwrap();

    assert_eq!(
        sid_before,
        kv_head_field(&result, "sid"),
        "sid must be preserved"
    );
    assert_eq!(
        created_at_before,
        kv_head_field(&result, "created_at"),
        "created_at must be preserved"
    );
}

#[test]
fn test_unset_uses_current_recipients_in_wrap() {
    let (initial, key_ctx, _temp, _ssh_temp) =
        setup_unset_test_ctx(&[("KEY1", "value1"), ("KEY2", "value2")]);
    let ctx = KvWriteContext::new("alice@example.com", &key_ctx);

    let initial = KvEncContent::new_unchecked(initial);
    let result = unset_kv_entry(&initial, "KEY1", &ctx).unwrap();

    let wrap = parse_kv_document(&result).unwrap().wrap;
    let recipients = wrap
        .wrap
        .iter()
        .map(|item| item.recipient_handle.as_str())
        .collect::<Vec<_>>();
    assert_eq!(recipients, vec!["alice@example.com"]);
}

#[test]
fn test_unset_preserves_other_entry_tokens() {
    let (initial, key_ctx, _temp, _ssh_temp) =
        setup_unset_test_ctx(&[("KEY1", "value1"), ("KEY2", "value2")]);
    let key2_token_before = kv_entry_token(&initial, "KEY2").unwrap();
    let ctx = KvWriteContext::new("alice@example.com", &key_ctx);

    let initial = KvEncContent::new_unchecked(initial);
    let result = unset_kv_entry(&initial, "KEY1", &ctx).unwrap();

    assert!(
        kv_entry_token(&result, "KEY1").is_none(),
        "KEY1 should be removed"
    );
    assert_eq!(
        key2_token_before,
        kv_entry_token(&result, "KEY2").unwrap(),
        "KEY2 token must be unchanged"
    );
}
