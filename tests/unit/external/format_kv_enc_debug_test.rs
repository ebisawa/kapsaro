// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Debug test for kv-enc v6 HPKE issue

use crate::keygen_helpers::{build_verified_private_key, build_verified_recipient_keys};
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{generate_temp_ssh_keypair_in_dir, keygen_test};
use ed25519_dalek::SigningKey;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::decrypt::decrypt_kv_document;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::format::kv::document::parse_kv_document;
use secretenv::format::kv::dotenv::{build_dotenv_string, parse_dotenv};
use secretenv::format::token::TokenCodec;
use secretenv::model::kv_enc::verified::VerifiedKvEncDocument;
use secretenv::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use tempfile::TempDir;

/// Generate Ed25519 signing key from seed for tests
fn generate_ed25519_keypair(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

#[test]
fn test_debug_hpke_single_recipient() {
    // Generate signing key for tests
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    // Generate single test key
    let ssh_temp = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub_path, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_temp);
    let (private, public) = keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    println!("Generated key:");
    println!("  member_handle: {}", public.protected.subject_handle);
    println!("  kid: {}", public.protected.kid);
    println!("  kem.x: {}", public.protected.identity.keys.kem.x);
    println!("  kem.d (first 20): {}", &private.keys.kem.d[..20]);

    // Simple input
    let input = "TEST_KEY=test_value\n";

    // Encrypt for single recipient
    let recipients = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = vec![public.clone()];
    let verified_members = build_verified_recipient_keys(&members);

    println!("\nEncrypting...");
    println!("  recipients: {:?}", recipients);

    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let kv_map = parse_dotenv(input).unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub: public.clone(),
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    println!("\nEncrypted kv-enc v6:");
    for (i, line) in encrypted.lines().enumerate() {
        if line.len() > 100 {
            println!("  Line {}: {}... ({} bytes)", i, &line[..100], line.len());
        } else {
            println!("  Line {}: {}", i, line);
        }
    }

    // Decrypt
    println!("\nDecrypting...");
    let doc = parse_kv_document(&encrypted).unwrap();
    let proof = SignatureVerificationProof::new(
        ALICE_MEMBER_HANDLE.to_string(),
        signer_kid.to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    let verified_doc = VerifiedKvEncDocument::new(doc, proof);
    let decrypted_key = build_verified_private_key(
        &private,
        ALICE_MEMBER_HANDLE,
        &public.protected.kid,
        "SHA256:test",
    );
    match decrypt_kv_document(
        &verified_doc,
        ALICE_MEMBER_HANDLE,
        &public.protected.kid,
        &decrypted_key,
        false,
    ) {
        Ok(decrypted_map_zeroizing) => {
            // Convert Zeroizing<Vec<u8>> to String at the boundary
            use std::collections::HashMap;
            let decrypted_map: HashMap<String, String> = decrypted_map_zeroizing
                .into_iter()
                .map(|(k, v)| (k, String::from_utf8(v.to_vec()).unwrap()))
                .collect();
            let decrypted = build_dotenv_string(&decrypted_map);
            println!("Success! Decrypted: {}", decrypted);
            let expected_map = parse_dotenv(input).unwrap();
            for (key, value) in expected_map {
                assert_eq!(
                    decrypted_map.get(&key).map(String::as_str),
                    Some(value.as_str())
                );
            }
        }
        Err(e) => {
            println!("Error: {:?}", e);
            panic!("Decryption failed: {:?}", e);
        }
    }
}
