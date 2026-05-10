// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for cli::identity_prompt

use std::env;
use std::fs;

use crate::app::context::ssh::SshKeyCandidateView;
use crate::test_utils::EnvGuard;
use serial_test::serial;
use tempfile::TempDir;

use super::{
    format_candidate, is_prompt_available, resolve_key_generation_github_user_with_prompt,
    select_ssh_key,
};

#[test]
fn test_select_ssh_key_empty_candidates_fails() {
    let candidates: Vec<SshKeyCandidateView> = vec![];
    let result = select_ssh_key(&candidates);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("No ssh-ed25519 key found"),
        "unexpected error: {err_msg}"
    );
}

#[test]
fn test_select_ssh_key_single_candidate_returns_zero() {
    let candidates = vec![SshKeyCandidateView {
        public_key: "ssh-ed25519 AAAA test@host".to_string(),
        fingerprint: "SHA256:abc123".to_string(),
        comment: "test@host".to_string(),
    }];
    let result = select_ssh_key(&candidates);
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_format_candidate_with_comment() {
    let candidate = SshKeyCandidateView {
        public_key: "ssh-ed25519 AAAA test@host".to_string(),
        fingerprint: "SHA256:abc123".to_string(),
        comment: "test@host".to_string(),
    };

    assert_eq!(format_candidate(&candidate), "SHA256:abc123 (test@host)");
}

#[test]
fn test_format_candidate_without_comment() {
    let candidate = SshKeyCandidateView {
        public_key: "ssh-ed25519 AAAA".to_string(),
        fingerprint: "SHA256:abc123".to_string(),
        comment: String::new(),
    };

    assert_eq!(format_candidate(&candidate), "SHA256:abc123");
}

#[test]
#[serial]
fn test_is_prompt_available_rejects_ci_environment() {
    let _guard = EnvGuard::new(&["CI"]);
    env::set_var("CI", "true");

    assert!(!is_prompt_available());
}

#[test]
fn test_select_ssh_key_multiple_candidates_non_tty_fails() {
    // Skip when running in an interactive terminal
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return;
    }

    let candidates = vec![
        SshKeyCandidateView {
            public_key: "ssh-ed25519 AAAA test@host".to_string(),
            fingerprint: "SHA256:abc123".to_string(),
            comment: "test@host".to_string(),
        },
        SshKeyCandidateView {
            public_key: "ssh-ed25519 BBBB work@host".to_string(),
            fingerprint: "SHA256:def456".to_string(),
            comment: "work@host".to_string(),
        },
    ];
    let result = select_ssh_key(&candidates);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Multiple Ed25519 keys found")
            && err_msg.contains("SECRETENV_SSH_IDENTITY"),
        "unexpected error: {err_msg}"
    );
}

#[test]
#[serial]
fn test_resolve_key_generation_github_user_with_prompt_returns_none_when_key_reuse() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    env::set_var("SECRETENV_GITHUB_USER", "env-user");

    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(
        false,
        None,
        Some(temp_home.path()),
        true,
        || {
            prompted = true;
            Ok(Some("prompt-user".to_string()))
        },
    )
    .unwrap();

    assert_eq!(result, None);
    assert!(!prompted);
}

#[test]
#[serial]
fn test_resolve_key_generation_github_user_with_prompt_prefers_config_before_prompt() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());
    fs::write(
        temp_home.path().join("config.toml"),
        "github_user = \"config-user\"\n",
    )
    .unwrap();

    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(
        true,
        None,
        Some(temp_home.path()),
        true,
        || {
            prompted = true;
            Ok(Some("prompt-user".to_string()))
        },
    )
    .unwrap();

    assert_eq!(result, Some("config-user".to_string()));
    assert!(!prompted);
}

#[test]
#[serial]
fn test_resolve_key_generation_github_user_with_prompt_uses_prompt_when_tty_and_unset() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(
        true,
        None,
        Some(temp_home.path()),
        true,
        || {
            prompted = true;
            Ok(Some("prompt-user".to_string()))
        },
    )
    .unwrap();

    assert_eq!(result, Some("prompt-user".to_string()));
    assert!(prompted);
}

#[test]
#[serial]
fn test_resolve_key_generation_github_user_with_prompt_returns_none_without_tty() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(
        true,
        None,
        Some(temp_home.path()),
        false,
        || {
            prompted = true;
            Ok(Some("prompt-user".to_string()))
        },
    )
    .unwrap();

    assert_eq!(result, None);
    assert!(!prompted);
}

#[test]
#[serial]
fn test_resolve_key_generation_github_user_with_prompt_allows_empty_prompt_input() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let result = resolve_key_generation_github_user_with_prompt(
        true,
        None,
        Some(temp_home.path()),
        true,
        || Ok(None),
    )
    .unwrap();

    assert_eq!(result, None);
}

#[test]
#[serial]
fn test_resolve_key_generation_github_user_with_prompt_rejects_invalid_prompt_input() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME", "SECRETENV_GITHUB_USER"]);
    let temp_home = TempDir::new().unwrap();
    env::set_var("SECRETENV_HOME", temp_home.path());

    let result = resolve_key_generation_github_user_with_prompt(
        true,
        None,
        Some(temp_home.path()),
        true,
        || Ok(Some("alice/keys".to_string())),
    );

    assert!(result.is_err());
}
