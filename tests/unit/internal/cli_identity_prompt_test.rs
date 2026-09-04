// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for cli::identity_prompt

use kapsaro_core::api::ssh::SshKeyCandidateView;

use super::{format_candidate, resolve_key_generation_github_user_with_prompt, select_ssh_key};

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
        err_msg.contains("Multiple Ed25519 keys found") && err_msg.contains("KAPSARO_SSH_IDENTITY"),
        "unexpected error: {err_msg}"
    );
}

#[test]
fn test_resolve_key_generation_github_user_with_prompt_returns_none_when_key_reuse() {
    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(
        false,
        Some("configured-user".to_string()),
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
fn test_resolve_key_generation_github_user_with_prompt_prefers_resolved_input() {
    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(
        true,
        Some("config-user".to_string()),
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
fn test_resolve_key_generation_github_user_with_prompt_uses_prompt_when_tty_and_unset() {
    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(true, None, true, || {
        prompted = true;
        Ok(Some("prompt-user".to_string()))
    })
    .unwrap();

    assert_eq!(result, Some("prompt-user".to_string()));
    assert!(prompted);
}

#[test]
fn test_resolve_key_generation_github_user_with_prompt_returns_none_without_tty() {
    let mut prompted = false;
    let result = resolve_key_generation_github_user_with_prompt(true, None, false, || {
        prompted = true;
        Ok(Some("prompt-user".to_string()))
    })
    .unwrap();

    assert_eq!(result, None);
    assert!(!prompted);
}

#[test]
fn test_resolve_key_generation_github_user_with_prompt_allows_empty_prompt_input() {
    let result =
        resolve_key_generation_github_user_with_prompt(true, None, true, || Ok(None)).unwrap();

    assert_eq!(result, None);
}

#[test]
fn test_resolve_key_generation_github_user_with_prompt_rejects_invalid_prompt_input() {
    let result = resolve_key_generation_github_user_with_prompt(true, None, true, || {
        Ok(Some("alice/keys".to_string()))
    });

    assert!(result.is_err());
}
