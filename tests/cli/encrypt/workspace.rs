// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace-related encryption tests

use crate::cli::common::{
    default_common_options, set_ssh_key_from_temp_dir, ALICE_MEMBER_ID, BOB_MEMBER_ID,
};
use crate::test_utils::{keygen_test, setup_test_workspace};
use secretenv::cli::encrypt;
use secretenv::cli::set;
use secretenv::format::kv;
use secretenv::format::schema::document::parse_kv_wrap_token;
use secretenv::model::kv_enc::header::KvWrap;
use std::fs;

#[test]
fn test_encrypt_member_id_mismatch() {
    // Setup test workspace with alice
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let members_dir = workspace_dir.join("members/active");
    let secrets_dir = workspace_dir.join("secrets");

    // Generate another key and tamper with member_id in the public key
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (_bob_private, mut bob_public) =
        keygen_test(BOB_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();
    // Tamper: filename is alice but content has bob's member_id
    bob_public.protected.member_id = BOB_MEMBER_ID.to_string();
    let alice_member_file = members_dir.join(format!("{}.json", ALICE_MEMBER_ID));
    fs::write(
        &alice_member_file,
        serde_json::to_string_pretty(&bob_public).unwrap(),
    )
    .unwrap();

    // Create test binary file
    let input_path = workspace_dir.join("test.bin");
    let input_content = b"binary test content";
    fs::write(&input_path, input_content).unwrap();

    // Create output path
    let encrypted_path = secrets_dir.join("test.encrypted");

    // Try to encrypt with alice as recipient
    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let encrypt_args = encrypt::EncryptArgs {
        common: common_opts,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        input: input_path.clone(),
        out: Some(encrypted_path.clone()),
    };

    // Should fail with member_id mismatch error
    let result = encrypt::run(encrypt_args);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("mismatch") || err_msg.contains("ID"),
        "Error should mention member_id mismatch: {}",
        err_msg
    );
}

#[test]
fn test_set_creates_default_file() {
    // Setup test workspace with alice and bob
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let secrets_dir = workspace_dir.join("secrets");

    // Define default kv-enc file path (does NOT exist yet)
    let kv_file_path = secrets_dir.join("default.kvenc");
    assert!(!kv_file_path.exists(), "File should not exist before test");

    // Set a key-value pair WITHOUT specifying recipients (should default to @all)
    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);
    common_opts.quiet = true; // Suppress output

    let set_args = set::SetArgs {
        common: common_opts,

        member_id: Some(ALICE_MEMBER_ID.to_string()),
        name: None,
        stdin: false,
        key: "DATABASE_URL".to_string(),
        value: Some("postgres://localhost/mydb".to_string()),
    };

    set::run(set_args).unwrap();

    // Verify file was created
    assert!(kv_file_path.exists(), "Should create default kv-enc file");

    // Verify file has kv-enc format
    let encrypted_content = fs::read_to_string(&kv_file_path).unwrap();
    assert!(
        encrypted_content.starts_with(kv::HEADER_LINE_V3),
        "Should have kv-enc v3 header"
    );

    // Verify both alice and bob are recipients (due to @all default)
    let lines: Vec<&str> = encrypted_content.lines().collect();
    let wrap_line = lines
        .iter()
        .find(|l| l.starts_with(":WRAP "))
        .expect("Should have WRAP line");
    let wrap_token = wrap_line.trim_start_matches(":WRAP ");

    // Decode wrap token
    let wrap_data: KvWrap = parse_kv_wrap_token(wrap_token).unwrap();

    // Check that both alice and bob are recipients
    let recipient_ids: Vec<String> = wrap_data.wrap.iter().map(|w| w.rid.clone()).collect();
    assert!(
        recipient_ids.contains(&ALICE_MEMBER_ID.to_string()),
        "Should include alice"
    );
    assert!(
        recipient_ids.contains(&BOB_MEMBER_ID.to_string()),
        "Should include bob"
    );

    // Verify the key exists in the file
    let kv_line = lines
        .iter()
        .find(|l| l.starts_with("DATABASE_URL "))
        .expect("Should have DATABASE_URL entry");
    assert!(
        kv_line.starts_with("DATABASE_URL "),
        "Should have DATABASE_URL key"
    );
}
