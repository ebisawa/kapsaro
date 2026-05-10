// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for pre-flight SSH key verification against GitHub.

use secretenv::io::github::http::GitHubKeyRecord;
use secretenv::io::verify_online::github::preflight::verify_ssh_key_on_github_with_api;
use secretenv::io::verify_online::github::{GitHubApiFuture, GitHubVerificationApi};
use secretenv::io::verify_online::VerificationStatus;
use secretenv::model::public_key::GithubAccount;
use secretenv::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const TEST_SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";

struct FakeGitHubApi {
    keys_result: Result<Vec<GitHubKeyRecord>>,
    calls: Arc<AtomicUsize>,
}

impl FakeGitHubApi {
    fn new(keys_result: Result<Vec<GitHubKeyRecord>>) -> Self {
        Self {
            keys_result,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl GitHubVerificationApi for FakeGitHubApi {
    fn fetch_user_by_id<'a>(&'a self, _account_id: u64) -> GitHubApiFuture<'a, (u64, String)> {
        Box::pin(async { unreachable!("pre-flight should not call fetch_user_by_id") })
    }

    fn fetch_keys<'a>(&'a self, _login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.keys_result {
                Ok(keys) => Ok(keys.clone()),
                Err(Error::Verify { rule, message }) => Err(Error::Verify {
                    rule: rule.clone(),
                    message: message.clone(),
                }),
                Err(other) => Err(Error::Verify {
                    rule: "V-GITHUB-API".to_string(),
                    message: other.to_string(),
                }),
            }
        })
    }
}

fn test_account() -> GithubAccount {
    GithubAccount {
        id: 42,
        login: "alice".to_string(),
    }
}

#[tokio::test]
async fn test_verify_ssh_key_on_github() {
    let api = FakeGitHubApi::new(Ok(vec![GitHubKeyRecord {
        id: 100,
        key: TEST_SSH_PUBKEY.to_string(),
    }]));

    let result =
        verify_ssh_key_on_github_with_api(TEST_SSH_PUBKEY, &test_account(), false, &api).await;

    let status = result.unwrap();
    assert_eq!(status, VerificationStatus::Verified);
}

#[tokio::test]
async fn test_verify_ssh_key_on_github_no_matching_key() {
    let api = FakeGitHubApi::new(Ok(vec![GitHubKeyRecord {
            id: 200,
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other@example.com".to_string(),
        }]));

    let result =
        verify_ssh_key_on_github_with_api(TEST_SSH_PUBKEY, &test_account(), false, &api).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Verify { rule, .. } if rule == "V-GITHUB-KEY-NEW"));
}

#[tokio::test]
async fn test_verify_ssh_key_on_github_no_keys_on_github() {
    let api = FakeGitHubApi::new(Ok(vec![]));

    let result =
        verify_ssh_key_on_github_with_api(TEST_SSH_PUBKEY, &test_account(), false, &api).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Verify { rule, .. } if rule == "V-GITHUB-KEY-NEW"));
}

#[tokio::test]
async fn test_verify_ssh_key_on_github_invalid_ssh_key() {
    let api = FakeGitHubApi::new(Ok(vec![]));

    let result =
        verify_ssh_key_on_github_with_api("invalid-key", &test_account(), false, &api).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_verify_ssh_key_on_github_rejects_invalid_key_before_api_call() {
    let api = FakeGitHubApi::new(Ok(vec![GitHubKeyRecord {
        id: 100,
        key: TEST_SSH_PUBKEY.to_string(),
    }]));

    let result =
        verify_ssh_key_on_github_with_api("invalid-key", &test_account(), false, &api).await;

    assert!(result.is_err());
    assert_eq!(api.call_count(), 0);
}

#[tokio::test]
async fn test_verify_ssh_key_on_github_propagates_keys_api_error() {
    let api = FakeGitHubApi::new(Err(Error::Verify {
        rule: "V-GITHUB-API".to_string(),
        message: "keys endpoint failed".to_string(),
    }));

    let result =
        verify_ssh_key_on_github_with_api(TEST_SSH_PUBKEY, &test_account(), false, &api).await;

    match result {
        Err(Error::Verify { rule, message }) => {
            assert_eq!(rule, "V-GITHUB-API");
            assert_eq!(message, "keys endpoint failed");
        }
        other => panic!("expected verify error, got {other:?}"),
    }
    assert_eq!(api.call_count(), 1);
}
