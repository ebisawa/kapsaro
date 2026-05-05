// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for GitHub account lookup by login.

use secretenv::io::github::account::{
    resolve_github_account_by_login_with_api, GitHubAccountLookupApi, GitHubAccountLookupFuture,
};
use secretenv::model::public_key::GithubAccount;
use secretenv::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct FakeGitHubAccountLookupApi {
    user_by_login_result: Result<GithubAccount>,
    calls: Arc<AtomicUsize>,
}

impl GitHubAccountLookupApi for FakeGitHubAccountLookupApi {
    fn fetch_user_by_login<'a>(
        &'a self,
        _login: &'a str,
    ) -> GitHubAccountLookupFuture<'a, GithubAccount> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.user_by_login_result {
                Ok(account) => Ok(account.clone()),
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

#[tokio::test]
async fn test_resolve_github_account_by_login_with_fake_api() {
    let api = FakeGitHubAccountLookupApi {
        user_by_login_result: Ok(GithubAccount {
            id: 42,
            login: "alice".to_string(),
        }),
        calls: Arc::new(AtomicUsize::new(0)),
    };

    let result = resolve_github_account_by_login_with_api("alice", false, &api).await;

    assert_eq!(
        result.unwrap(),
        GithubAccount {
            id: 42,
            login: "alice".to_string(),
        }
    );
    assert_eq!(api.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_resolve_github_account_by_login_rejects_invalid_login_before_api_call() {
    let calls = Arc::new(AtomicUsize::new(0));
    let api = FakeGitHubAccountLookupApi {
        user_by_login_result: Ok(GithubAccount {
            id: 42,
            login: "alice".to_string(),
        }),
        calls: Arc::clone(&calls),
    };

    let result = resolve_github_account_by_login_with_api("../alice", false, &api).await;

    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
