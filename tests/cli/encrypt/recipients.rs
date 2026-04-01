// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient-related encryption tests
//!
//! encrypt は常に workspace の全 active メンバーを recipients とする。
//! --recipients オプションは廃止。

use crate::cli::common::{
    default_common_options, set_ssh_key_from_temp_dir, ALICE_MEMBER_ID, BOB_MEMBER_ID,
    CAROL_MEMBER_ID,
};
use crate::test_utils::setup_test_workspace;
use secretenv::cli::encrypt;
use std::fs;

#[test]
fn test_encrypt_recipients_are_all_active_members() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID, CAROL_MEMBER_ID]);

    let input_path = workspace_dir.join("secret.bin");
    fs::write(&input_path, b"secret data").unwrap();
    let output_path = workspace_dir.join("secret.encrypted");

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let args = encrypt::EncryptArgs {
        common: common_opts,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        input: input_path,
        out: Some(output_path.clone()),
    };
    encrypt::run(args).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let wrap = parsed["protected"]["wrap"].as_array().unwrap();
    assert_eq!(wrap.len(), 3, "All 3 active members should be recipients");

    let rids: Vec<&str> = wrap.iter().map(|w| w["rid"].as_str().unwrap()).collect();
    assert!(rids.contains(&ALICE_MEMBER_ID));
    assert!(rids.contains(&BOB_MEMBER_ID));
    assert!(rids.contains(&CAROL_MEMBER_ID));
}

#[test]
fn test_encrypt_workspace_required() {
    use crate::test_utils::{setup_test_keystore, with_temp_cwd};
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let test_dir = temp_dir.path();
    with_temp_cwd(test_dir, || {
        let input_path = test_dir.join("test.bin");
        fs::write(&input_path, b"data").unwrap();

        let mut common_opts = default_common_options();
        common_opts.home = Some(temp_dir.path().to_path_buf());
        set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

        let args = encrypt::EncryptArgs {
            common: common_opts,
            member_id: Some(ALICE_MEMBER_ID.to_string()),
            input: input_path,
            out: Some(test_dir.join("out.encrypted")),
        };
        let result = encrypt::run(args);
        assert!(result.is_err(), "Should fail without workspace");
    })
}

#[test]
fn test_encrypt_rejects_recipients_option() {
    // --recipients オプションは廃止されており、"unexpected argument" エラーになるべき
    use crate::cli::common::cmd;
    use predicates::prelude::*;

    cmd()
        .arg("encrypt")
        .arg("--recipients")
        .arg("alice@example.com")
        .arg("some_file.txt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
}
