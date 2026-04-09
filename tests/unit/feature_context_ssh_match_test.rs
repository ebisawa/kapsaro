// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::ssh::{find_ssh_candidate_by_fingerprint, SshKeyCandidateView};

fn build_candidate(fingerprint: &str, comment: &str) -> SshKeyCandidateView {
    SshKeyCandidateView {
        public_key: format!("ssh-ed25519 AAAA{}data {}", fingerprint, comment),
        fingerprint: fingerprint.to_string(),
        comment: comment.to_string(),
    }
}

#[test]
fn test_find_candidate_by_fingerprint_single_match() {
    let candidates = vec![
        build_candidate("SHA256:aaaa", "key-a"),
        build_candidate("SHA256:bbbb", "key-b"),
    ];

    let result = find_ssh_candidate_by_fingerprint(&candidates, "SHA256:bbbb").unwrap();
    assert_eq!(result.fingerprint, "SHA256:bbbb");
    assert_eq!(result.comment, "key-b");
}

#[test]
fn test_find_candidate_by_fingerprint_first_of_many() {
    let candidates = vec![
        build_candidate("SHA256:xxxx", "first"),
        build_candidate("SHA256:yyyy", "second"),
        build_candidate("SHA256:zzzz", "third"),
    ];

    let result = find_ssh_candidate_by_fingerprint(&candidates, "SHA256:xxxx").unwrap();
    assert_eq!(result.fingerprint, "SHA256:xxxx");
    assert_eq!(result.comment, "first");
}

#[test]
fn test_find_candidate_by_fingerprint_no_match_error() {
    let candidates = vec![
        build_candidate("SHA256:aaaa", "key-a"),
        build_candidate("SHA256:bbbb", "key-b"),
    ];

    let err = find_ssh_candidate_by_fingerprint(&candidates, "SHA256:missing")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("SHA256:missing"),
        "error should contain fingerprint: {err}"
    );
    assert!(
        err.contains("ssh-agent"),
        "error should mention ssh-agent: {err}"
    );
}

#[test]
fn test_find_candidate_by_fingerprint_empty_candidates_error() {
    let candidates: Vec<SshKeyCandidateView> = vec![];

    let err = find_ssh_candidate_by_fingerprint(&candidates, "SHA256:any")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("SHA256:any"),
        "error should contain fingerprint: {err}"
    );
    assert!(
        err.contains("ssh-agent"),
        "error should mention ssh-agent: {err}"
    );
}
