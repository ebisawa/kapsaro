// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH agent validation - key matching logic

use secretenv::io::ssh::agent::validation::{find_key_in_agent, AgentIdentity};
use secretenv::io::ssh::protocol::parse::decode_ssh_public_key_blob;

const ED25519_KEY_NO_COMMENT: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT";

const ED25519_KEY_WITH_COMMENT: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT test-key-1";

const ED25519_OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM4In5W7fTd0kSImZziZtVYeU8IuJFGh2zSPQSH9kc1f test-key-2";

#[test]
fn test_find_key_matches_same_key_with_different_comments() {
    let key_no_comment = decode_ssh_public_key_blob(ED25519_KEY_NO_COMMENT).unwrap();
    let key_with_comment = decode_ssh_public_key_blob(ED25519_KEY_WITH_COMMENT).unwrap();

    let identities = vec![AgentIdentity::new(
        key_with_comment,
        "test-key-1".to_string(),
    )];
    let result = find_key_in_agent(&identities, &key_no_comment).unwrap();
    assert!(result, "key should match regardless of comment difference");
}

#[test]
fn test_find_key_matches_identical_keys() {
    let key1 = decode_ssh_public_key_blob(ED25519_KEY_WITH_COMMENT).unwrap();
    let key2 = decode_ssh_public_key_blob(ED25519_KEY_WITH_COMMENT).unwrap();

    let identities = vec![AgentIdentity::new(key1, "test-key-1".to_string())];
    let result = find_key_in_agent(&identities, &key2).unwrap();
    assert!(result);
}

#[test]
fn test_find_key_no_match_different_key() {
    let agent_key = decode_ssh_public_key_blob(ED25519_OTHER_KEY).unwrap();
    let target_key = decode_ssh_public_key_blob(ED25519_KEY_NO_COMMENT).unwrap();

    let identities = vec![AgentIdentity::new(agent_key, "test-key-2".to_string())];
    let result = find_key_in_agent(&identities, &target_key).unwrap();
    assert!(!result);
}

#[test]
fn test_find_key_empty_identities() {
    let target_key = decode_ssh_public_key_blob(ED25519_KEY_NO_COMMENT).unwrap();
    let identities: Vec<AgentIdentity> = vec![];
    let result = find_key_in_agent(&identities, &target_key).unwrap();
    assert!(!result);
}
