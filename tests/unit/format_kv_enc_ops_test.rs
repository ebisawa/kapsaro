// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for kv-enc v3 encryption/decryption operations

use crate::keygen_helpers::{make_decrypted_private_key_plaintext, make_verified_members};
use crate::test_utils::{create_temp_ssh_keypair_in_dir, keygen_test};
use crate::test_utils::{ALICE_MEMBER_ID, BOB_MEMBER_ID, TEST_MEMBER_ID};
use ed25519_dalek::SigningKey;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::decrypt::decrypt_kv_document;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot, KvSetResult,
    KvWriteContext,
};
use secretenv::feature::kv::types::KvInputEntry;
use secretenv::format::content::KvEncContent;
use secretenv::format::kv::document::parse_kv_document;
use secretenv::format::kv::dotenv::{build_dotenv_string, parse_dotenv};
use secretenv::format::kv::enc::canonical::parse_kv_wrap;
use secretenv::format::schema::document::{parse_kv_head_token, parse_kv_wrap_token};
use secretenv::format::token::TokenCodec;
use secretenv::io::workspace::members::{list_active_member_ids, load_member_files};
use secretenv::model::identity::{Kid, MemberId};
use secretenv::model::kv_enc::verified::VerifiedKvEncDocument;
use secretenv::model::public_key::PublicKey;
use secretenv::model::verification::{SignatureVerificationProof, VerifyingKeySource};

/// Generate Ed25519 signing key from seed for tests
fn generate_ed25519_keypair(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

/// Helper function to decrypt kv-enc content for tests (creates Verified wrapper)
fn decrypt_kv_document_for_test(
    encrypted: &str,
    member_id: &str,
    kid: &str,
    private: &secretenv::model::private_key::PrivateKeyPlaintext,
    signer_kid: &str,
) -> std::collections::HashMap<String, String> {
    let doc = parse_kv_document(encrypted).unwrap();
    let proof = SignatureVerificationProof::new(
        member_id.to_string(),
        signer_kid.to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    let verified_doc = VerifiedKvEncDocument::new(doc, proof);
    // Wrap private key in Decrypted for API
    let decrypted_key =
        make_decrypted_private_key_plaintext(private, member_id, kid, "sha256:test");
    let kv_map_zeroizing =
        decrypt_kv_document(&verified_doc, member_id, kid, &decrypted_key, false).unwrap();
    // Convert Zeroizing<Vec<u8>> to String at the boundary
    kv_map_zeroizing
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8(v.to_vec()).unwrap()))
        .collect()
}

#[test]
fn test_encrypt_and_decrypt_kv() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    // Generate test keys
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private1, public1) = keygen_test(ALICE_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();
    let (private2, public2) = keygen_test(BOB_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();

    // Input dotenv
    let input = "DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n";

    // Encrypt for two recipients
    let members: Vec<PublicKey> = vec![public1.clone(), public2.clone()];
    let verified_members = make_verified_members(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub: public1.clone(),
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Verify structure
    assert!(encrypted.starts_with(":SECRETENV_KV 3\n"));
    assert!(encrypted.contains(":HEAD "));
    assert!(encrypted.contains(":WRAP "));
    assert!(encrypted.contains("DATABASE_URL "));
    assert!(encrypted.contains("API_KEY "));

    // Decrypt with alice's key
    let decrypted_map1 = decrypt_kv_document_for_test(
        &encrypted,
        ALICE_MEMBER_ID,
        &public1.protected.kid,
        &private1,
        signer_kid,
    );
    let decrypted1 = build_dotenv_string(&decrypted_map1);
    // Keys are sorted alphabetically in output
    assert_eq!(
        decrypted1,
        "API_KEY=secret123\nDATABASE_URL=postgres://localhost\n"
    );

    // Decrypt with bob's key
    let decrypted_map2 = decrypt_kv_document_for_test(
        &encrypted,
        BOB_MEMBER_ID,
        &public2.protected.kid,
        &private2,
        signer_kid,
    );
    let decrypted2 = build_dotenv_string(&decrypted_map2);
    assert_eq!(
        decrypted2,
        "API_KEY=secret123\nDATABASE_URL=postgres://localhost\n"
    );
}

#[test]
fn test_encrypt_empty_input() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (_, public) = keygen_test(TEST_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();

    let input = "";
    let signer_pub = public.clone();
    let members = vec![public];
    let verified_members = make_verified_members(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Should have header, HEAD line, WRAP line, and SIG line (v3 requires signature)
    assert!(encrypted.starts_with(":SECRETENV_KV 3\n"));
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
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(TEST_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();
    let test_kid = public.protected.kid.clone();

    let input = r#"# This is a comment
DATABASE_URL=postgres://localhost

# Another comment
API_KEY=secret123
"#;

    let signer_pub = public.clone();
    let members = vec![public];
    let verified_members = make_verified_members(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Comments and blank lines from dotenv input should be filtered out in kv-enc output
    assert!(encrypted.contains("DATABASE_URL "));
    assert!(encrypted.contains("API_KEY "));
    assert!(!encrypted.contains("# This is a comment"));

    // Decrypt
    let decrypted_map =
        decrypt_kv_document_for_test(&encrypted, TEST_MEMBER_ID, &test_kid, &private, signer_kid);
    let decrypted = build_dotenv_string(&decrypted_map);

    // Should only contain the two KEY=VALUE lines
    let lines: Vec<&str> = decrypted.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2);
    assert!(decrypted.contains("DATABASE_URL=postgres://localhost"));
    assert!(decrypted.contains("API_KEY=secret123"));
}

#[test]
fn test_large_value_in_kv_enc() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(TEST_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();
    let test_kid = public.protected.kid.clone();

    // Create input with a large value
    let large_value = "A".repeat(500);
    let input = format!("LARGE_KEY={}\n", large_value);

    let signer_pub = public.clone();
    let members = vec![public];
    let verified_members = make_verified_members(&members);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(&input).unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Decrypt and verify correctness
    let decrypted_map =
        decrypt_kv_document_for_test(&encrypted, TEST_MEMBER_ID, &test_kid, &private, signer_kid);
    let decrypted = build_dotenv_string(&decrypted_map);
    assert_eq!(decrypted, format!("LARGE_KEY={}\n", large_value));
}

#[test]
fn test_wrap_line_with_many_recipients() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    // Create multiple recipients to make WRAP larger
    // Generate all keys first and keep them
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let mut keys = Vec::new();
    for i in 0..10 {
        let email = format!("user{}@example.com", i);
        keys.push(keygen_test(&email, &ssh_priv, &ssh_pub_content).unwrap());
    }

    let members: Vec<PublicKey> = keys.iter().map(|(_, pub_key)| pub_key.clone()).collect();
    let verified_members = make_verified_members(&members);
    let (private, _) = &keys[0]; // Use the first user's private key

    let input = "KEY=value\n";
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub: members[0].clone(),
            debug: false,
        },
        TokenCodec::JsonJcs,
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
    let wrap_data: secretenv::model::kv_enc::header::KvWrap =
        parse_kv_wrap_token(wrap_token).unwrap();
    let user_kid = wrap_data
        .wrap
        .iter()
        .find(|w| w.rid == "user0@example.com")
        .map(|w| w.kid.as_str())
        .expect("Should find wrap for user0@example.com");
    let decrypted_map = decrypt_kv_document_for_test(
        &encrypted,
        "user0@example.com",
        user_kid,
        private,
        signer_kid,
    );
    let decrypted = build_dotenv_string(&decrypted_map);
    assert_eq!(decrypted, "KEY=value\n");
}

// ============================================================
// set_kv_entry: 効率化テスト（sid・created_at・WRAP トークン不変）
// ============================================================

fn signing_key_from_private(
    private_key: &secretenv::model::private_key::PrivateKeyPlaintext,
) -> ed25519_dalek::SigningKey {
    use base64::Engine;
    let sig_d: Vec<u8> = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&private_key.keys.sig.d)
        .unwrap();
    ed25519_dalek::SigningKey::from_bytes(sig_d.as_slice().try_into().unwrap())
}

fn setup_crypto_ctx_for_test(
    member_id: &str,
    kid: &str,
    keystore_root: &std::path::Path,
    private_key: &secretenv::model::private_key::PrivateKeyPlaintext,
) -> secretenv::feature::context::crypto::CryptoContext {
    let signing_key = signing_key_from_private(private_key);

    let verified_private =
        make_decrypted_private_key_plaintext(private_key, member_id, kid, "sha256:test");

    // Derive workspace path from keystore_root (sibling directory)
    let workspace_path = keystore_root.parent().map(|p| p.join("workspace"));

    let pub_key_source: Box<dyn secretenv::io::keystore::public_key_source::PublicKeySource> =
        Box::new(
            secretenv::io::keystore::public_key_source::KeystorePublicKeySource::new(
                keystore_root.to_path_buf(),
            ),
        );

    secretenv::feature::context::crypto::CryptoContext {
        member_id: MemberId::try_from(member_id.to_string()).unwrap(),
        kid: Kid::try_from(kid.to_string()).unwrap(),
        pub_key_source,
        workspace_path,
        private_key: verified_private,
        signing_key,
        expires_at: "2099-12-31T23:59:59Z".to_string(),
    }
}

fn make_initial_kv_doc(
    member_id: &str,
    kid: &str,
    keystore_root: &std::path::Path,
    private_key: &secretenv::model::private_key::PrivateKeyPlaintext,
    public_key: &secretenv::model::public_key::PublicKey,
    entries: &[(&str, &str)],
) -> String {
    let signing_key = signing_key_from_private(private_key);

    crate::test_utils::save_public_key(keystore_root, member_id, kid, public_key).unwrap();

    // Create workspace with active member for signature verification
    let workspace_dir = keystore_root.parent().unwrap().join("workspace");
    let members_dir = workspace_dir.join("members/active");
    std::fs::create_dir_all(&members_dir).unwrap();
    std::fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();
    let member_file = members_dir.join(format!("{}.json", member_id));
    std::fs::write(
        &member_file,
        serde_json::to_string_pretty(public_key).unwrap(),
    )
    .unwrap();

    let verified_members = make_verified_members(std::slice::from_ref(public_key));

    let mut kv_map = std::collections::HashMap::new();
    for (k, v) in entries {
        kv_map.insert(k.to_string(), v.to_string());
    }

    secretenv::feature::kv::encrypt::encrypt_kv_document(
        &kv_map,
        &verified_members,
        &secretenv::feature::envelope::signature::SigningContext {
            signing_key: &signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
        secretenv::format::token::TokenCodec::JsonJcs,
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
    use secretenv::model::kv_enc::header::KvHeader;
    let token = content
        .lines()
        .find(|l| l.starts_with(":HEAD "))
        .unwrap()
        .strip_prefix(":HEAD ")
        .unwrap();
    let head: KvHeader = parse_kv_head_token(token).unwrap();
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
) -> secretenv::Result<KvSetResult> {
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
) -> secretenv::Result<String> {
    let workspace_root =
        ctx.key_ctx
            .workspace_path
            .as_deref()
            .ok_or_else(|| secretenv::Error::Config {
                message: "Workspace is required for kv mutation".to_string(),
            })?;
    let recipients = build_recipient_snapshot(workspace_root)?;
    unset_kv_entry_with_recipients(content, key, &recipients, ctx)
}

fn build_recipient_snapshot(
    workspace_root: &std::path::Path,
) -> secretenv::Result<KvRecipientSnapshot> {
    let member_ids = list_active_member_ids(workspace_root)?;
    let public_keys = load_member_files(workspace_root, &member_ids)?;
    let verified_members =
        secretenv::feature::verify::public_key::verify_recipient_public_keys(&public_keys, false)?;
    Ok(KvRecipientSnapshot {
        member_ids,
        verified_members,
    })
}

#[test]
fn test_set_existing_file_preserves_sid() {
    let member_id = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();

    let temp = tempfile::TempDir::new().unwrap();
    let keystore_root = temp.path().join("keys");

    let initial = make_initial_kv_doc(
        member_id,
        &kid,
        &keystore_root,
        &private,
        &public,
        &[("KEY1", "value1")],
    );
    let sid_before = kv_head_field(&initial, "sid");
    let created_at_before = kv_head_field(&initial, "created_at");

    let key_ctx = setup_crypto_ctx_for_test(member_id, &kid, &keystore_root, &private);
    let ctx = KvWriteContext::new(member_id, &key_ctx, false);
    let entries = vec![("KEY2".to_string(), "value2".to_string())];
    let initial_content = KvEncContent::new_unchecked(initial);
    let workspace_dir = temp.path().join("workspace");
    let result = set_kv_entry(Some(&initial_content), &entries, &workspace_dir, &ctx).unwrap();

    assert_eq!(
        sid_before,
        kv_head_field(result.encrypted.as_str(), "sid"),
        "sid must be preserved"
    );
    assert_eq!(
        created_at_before,
        kv_head_field(result.encrypted.as_str(), "created_at"),
        "created_at must be preserved"
    );
}

#[test]
fn test_set_existing_file_uses_current_recipients_in_wrap() {
    let member_id = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();

    let temp = tempfile::TempDir::new().unwrap();
    let keystore_root = temp.path().join("keys");

    let initial = make_initial_kv_doc(
        member_id,
        &kid,
        &keystore_root,
        &private,
        &public,
        &[("KEY1", "value1")],
    );
    let key_ctx = setup_crypto_ctx_for_test(member_id, &kid, &keystore_root, &private);
    let ctx = KvWriteContext::new(member_id, &key_ctx, false);
    let entries = vec![("KEY2".to_string(), "value2".to_string())];
    let initial_content = KvEncContent::new_unchecked(initial);
    let workspace_dir = temp.path().join("workspace");
    let result = set_kv_entry(Some(&initial_content), &entries, &workspace_dir, &ctx).unwrap();

    let (_, _, wrap) = parse_kv_wrap(result.encrypted.as_str()).unwrap();
    let recipients = wrap
        .wrap
        .iter()
        .map(|item| item.rid.as_str())
        .collect::<Vec<_>>();
    assert_eq!(recipients, vec![member_id]);
}

#[test]
fn test_set_existing_file_preserves_other_entry_tokens() {
    let member_id = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();

    let temp = tempfile::TempDir::new().unwrap();
    let keystore_root = temp.path().join("keys");

    let initial = make_initial_kv_doc(
        member_id,
        &kid,
        &keystore_root,
        &private,
        &public,
        &[("KEY1", "value1"), ("KEY2", "value2")],
    );
    let key1_token_before = kv_entry_token(&initial, "KEY1").unwrap();
    let key2_token_before = kv_entry_token(&initial, "KEY2").unwrap();

    let key_ctx = setup_crypto_ctx_for_test(member_id, &kid, &keystore_root, &private);
    let ctx = KvWriteContext::new(member_id, &key_ctx, false);
    let entries = vec![("KEY3".to_string(), "value3".to_string())];
    let initial_content = KvEncContent::new_unchecked(initial);
    let workspace_dir = temp.path().join("workspace");
    let result = set_kv_entry(Some(&initial_content), &entries, &workspace_dir, &ctx).unwrap();

    assert_eq!(
        key1_token_before,
        kv_entry_token(result.encrypted.as_str(), "KEY1").unwrap(),
        "KEY1 token must be unchanged"
    );
    assert_eq!(
        key2_token_before,
        kv_entry_token(result.encrypted.as_str(), "KEY2").unwrap(),
        "KEY2 token must be unchanged"
    );
}

// ============================================================
// unset_kv_entry: 効率化テスト
// ============================================================

/// unset テスト用の共通セットアップ
fn make_unset_test_ctx(
    entries: &[(&str, &str)],
) -> (
    String,                                             // initial content
    secretenv::feature::context::crypto::CryptoContext, // key context
    tempfile::TempDir,                                  // must be kept alive
    tempfile::TempDir,                                  // SSH temp dir - must be kept alive
) {
    let member_id = "alice@example.com";
    let ssh_temp = tempfile::TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = public.protected.kid.clone();
    let temp = tempfile::TempDir::new().unwrap();
    let keystore_root = temp.path().join("keys");

    let initial = make_initial_kv_doc(member_id, &kid, &keystore_root, &private, &public, entries);

    let key_ctx = setup_crypto_ctx_for_test(member_id, &kid, &keystore_root, &private);
    (initial, key_ctx, temp, ssh_temp)
}

#[test]
fn test_unset_preserves_sid_and_created_at() {
    let (initial, key_ctx, _temp, _ssh_temp) =
        make_unset_test_ctx(&[("KEY1", "value1"), ("KEY2", "value2")]);
    let sid_before = kv_head_field(&initial, "sid");
    let created_at_before = kv_head_field(&initial, "created_at");
    let ctx = KvWriteContext::new("alice@example.com", &key_ctx, false);

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
        make_unset_test_ctx(&[("KEY1", "value1"), ("KEY2", "value2")]);
    let ctx = KvWriteContext::new("alice@example.com", &key_ctx, false);

    let initial = KvEncContent::new_unchecked(initial);
    let result = unset_kv_entry(&initial, "KEY1", &ctx).unwrap();

    let (_, _, wrap) = parse_kv_wrap(&result).unwrap();
    let recipients = wrap
        .wrap
        .iter()
        .map(|item| item.rid.as_str())
        .collect::<Vec<_>>();
    assert_eq!(recipients, vec!["alice@example.com"]);
}

#[test]
fn test_unset_preserves_other_entry_tokens() {
    let (initial, key_ctx, _temp, _ssh_temp) =
        make_unset_test_ctx(&[("KEY1", "value1"), ("KEY2", "value2")]);
    let key2_token_before = kv_entry_token(&initial, "KEY2").unwrap();
    let ctx = KvWriteContext::new("alice@example.com", &key_ctx, false);

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

#[test]
fn test_unset_key_not_found_error() {
    let (initial, key_ctx, _temp, _ssh_temp) = make_unset_test_ctx(&[("KEY1", "value1")]);
    let ctx = KvWriteContext::new("alice@example.com", &key_ctx, false);

    let initial = KvEncContent::new_unchecked(initial);
    let result = unset_kv_entry(&initial, "NONEXISTENT", &ctx);

    assert!(
        result.is_err(),
        "unset of nonexistent key should return error"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("NONEXISTENT"),
        "error should mention the missing key: {}",
        err_msg
    );
}
