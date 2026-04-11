// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub account lookup helpers for key generation.

use super::http::{build_http_client, fetch_github_user_by_login};
use crate::model::public_key::GithubAccount;
use crate::Result;
use std::future::Future;
use std::pin::Pin;
use tracing::debug;

pub type GitHubAccountLookupFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait GitHubAccountLookupApi {
    fn fetch_user_by_login<'a>(
        &'a self,
        login: &'a str,
    ) -> GitHubAccountLookupFuture<'a, GithubAccount>;
}

struct GitHubAccountLookupClient {
    client: reqwest::Client,
}

impl GitHubAccountLookupClient {
    fn new() -> Result<Self> {
        Ok(Self {
            client: build_http_client()?,
        })
    }
}

impl GitHubAccountLookupApi for GitHubAccountLookupClient {
    fn fetch_user_by_login<'a>(
        &'a self,
        login: &'a str,
    ) -> GitHubAccountLookupFuture<'a, GithubAccount> {
        Box::pin(async move { fetch_github_user_by_login(&self.client, login).await })
    }
}

pub async fn resolve_github_account_by_login(login: &str, verbose: bool) -> Result<GithubAccount> {
    let api = GitHubAccountLookupClient::new()?;
    resolve_github_account_by_login_with_api(login, verbose, &api).await
}

pub async fn resolve_github_account_by_login_with_api(
    login: &str,
    verbose: bool,
    api: &impl GitHubAccountLookupApi,
) -> Result<GithubAccount> {
    if verbose {
        debug!(
            "[VERIFY] GitHub API: GET https://api.github.com/users/{}",
            login
        );
    }

    let account = api.fetch_user_by_login(login).await?;

    if verbose {
        debug!(
            "[VERIFY] GitHub API: user id={}, login={}",
            account.id, account.login
        );
    }

    Ok(account)
}
