// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace-related encryption tests

use crate::cli::common::{
    cmd, default_common_options, set_ssh_key_from_temp_dir, ALICE_MEMBER_ID, BOB_MEMBER_ID,
};
use crate::test_utils::{
    build_expiring_soon_timestamp, keygen_test, setup_member_key_context, setup_test_workspace,
    setup_trust_store_for_workspace, sync_active_public_key_to_workspace,
    update_active_private_key_expires_at,
};
use predicates::prelude::*;
use secretenv::cli::encrypt;
use secretenv::cli::set;
use secretenv::format::kv;
use secretenv::format::schema::document::parse_kv_wrap_token;
use secretenv::model::kv_enc::header::KvWrap;
use std::fs;

#[cfg(unix)]
use secretenv::io::trust::paths::trust_store_file_path;

#[test]
fn test_encrypt_uses_member_file_contents_not_filename() {
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
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    // Create test binary file
    let input_path = workspace_dir.join("test.bin");
    let input_content = b"binary test content";
    fs::write(&input_path, input_content).unwrap();

    // Create output path
    let encrypted_path = secrets_dir.join("test.encrypted");

    // Encrypt should use the document content as the source of truth.
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

    encrypt::run(encrypt_args).unwrap();

    let encrypted = fs::read_to_string(&encrypted_path).unwrap();
    let document: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
    let recipients = document["protected"]["wrap"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["rid"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();

    assert_eq!(recipients, vec![BOB_MEMBER_ID.to_string()]);
}

#[test]
fn test_set_creates_default_file() {
    // Setup test workspace with alice and bob
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let secrets_dir = workspace_dir.join("secrets");
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

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

#[cfg(unix)]
#[test]
fn test_encrypt_surfaces_insecure_trust_store_warning_on_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let trust_path = trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let input_path = workspace_dir.join("warn.txt");
    fs::write(&input_path, b"warning check").unwrap();
    let output_path = workspace_dir.join("warn.txt.encrypted");
    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");

    cmd()
        .arg("encrypt")
        .arg(input_path)
        .arg("--out")
        .arg(output_path)
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains("Insecure permissions"));
}

#[test]
fn test_encrypt_rejects_strict_key_checking_no() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let input_path = workspace_dir.join("strict-no.txt");
    fs::write(&input_path, b"strict no check").unwrap();
    let output_path = workspace_dir.join("strict-no.txt.encrypted");
    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");

    cmd()
        .arg("encrypt")
        .arg(&input_path)
        .arg("--out")
        .arg(&output_path)
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_key)
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not allowed").and(predicate::str::contains("encrypt")));
}

#[test]
fn test_encrypt_surfaces_private_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_ID, &expires_at);

    let input_path = workspace_dir.join("expiry.txt");
    fs::write(&input_path, b"warning check").unwrap();
    let output_path = workspace_dir.join("expiry.txt.encrypted");
    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");

    cmd()
        .arg("encrypt")
        .arg(input_path)
        .arg("--out")
        .arg(output_path)
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning: Private key expires in"));
}

#[test]
fn test_encrypt_surfaces_recipient_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_ID, &expires_at);
    sync_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_ID).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let input_path = workspace_dir.join("recipient-expiry.txt");
    fs::write(&input_path, b"warning check").unwrap();
    let output_path = workspace_dir.join("recipient-expiry.txt.encrypted");
    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");

    cmd()
        .arg("encrypt")
        .arg(input_path)
        .arg("--out")
        .arg(output_path)
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: Recipient public key for 'bob@example.com' expires in",
        ));
}
