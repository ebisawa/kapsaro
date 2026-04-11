// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub account lookup helpers for key generation.

use crate::model::public_key::GithubAccount;
use crate::{Error, Result};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use tracing::debug;

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
}

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

fn build_http_client() -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .user_agent(format!("secretenv/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10));

    builder.build().map_err(|e| Error::Config {
        message: format!("Failed to create HTTP client: {}", e),
    })
}

fn build_github_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    let request = client.get(url);
    apply_github_auth(request)
}

fn apply_github_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        return request.header("Authorization", format!("Bearer {}", token));
    }
    request
}

async fn fetch_github_user_by_login(
    client: &reqwest::Client,
    login: &str,
) -> Result<GithubAccount> {
    let url = format!("https://api.github.com/users/{}", login);
    let request = build_github_request(client, &url);
    let response = request.send().await.map_err(|e| Error::Verify {
        rule: "V-GITHUB-API".to_string(),
        message: format!("Failed to fetch GitHub user: {}", e),
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::Verify {
            rule: "V-GITHUB-API".to_string(),
            message: format!(
                "GitHub user not found for login '{}' (status: {})",
                login, status
            ),
        });
    }

    let user: GitHubUser = response.json().await.map_err(|e| Error::Verify {
        rule: "V-GITHUB-API".to_string(),
        message: format!("Failed to parse GitHub user response: {}", e),
    })?;

    Ok(GithubAccount {
        id: user.id,
        login: user.login,
    })
}
