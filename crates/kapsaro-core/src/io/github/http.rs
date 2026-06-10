// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! HTTP transport helpers for GitHub REST API access.
//!
//! Shared between pre-flight key verification, online verification, and
//! key-generation account lookup.

use crate::model::public_key::GithubAccount;
use crate::support::validation;
use crate::{Error, Result};
use serde::Deserialize;

const GITHUB_API_BASE_URL: &str = "https://api.github.com";

/// SSH key metadata fetched from GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubKeyRecord {
    pub id: i64,
    pub key: String,
}

/// GitHub API response for user keys.
#[derive(Debug, Deserialize)]
struct GitHubKey {
    id: i64,
    key: String,
}

/// GitHub REST API user response.
#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
}

/// Build an HTTP client for GitHub API requests.
pub(crate) fn build_http_client() -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .user_agent(format!("kapsaro/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10));

    builder
        .build()
        .map_err(|e| Error::build_config_error(format!("Failed to create HTTP client: {}", e)))
}

fn build_github_api_url(path_segments: &[&str]) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(GITHUB_API_BASE_URL).map_err(|e| {
        Error::build_config_error(format!("Failed to parse GitHub API base URL: {}", e))
    })?;
    build_github_api_url_from_base(url, path_segments)
}

fn build_github_api_url_from_base(
    mut url: reqwest::Url,
    path_segments: &[&str],
) -> Result<reqwest::Url> {
    url.path_segments_mut()
        .map_err(|_| Error::build_config_error("Failed to build GitHub API URL".to_string()))?
        .extend(path_segments);
    Ok(url)
}

/// Generic user lookup used by both `fetch_github_user_by_id` and
/// `fetch_github_user_by_login`.
///
/// `context_label` is embedded into the "not found" error message
/// (e.g. `"account id '42'"` or `"login 'alice'"`).
async fn fetch_github_user_api<T, F>(
    client: &reqwest::Client,
    url: reqwest::Url,
    context_label: &str,
    transform: F,
) -> Result<T>
where
    F: FnOnce(GitHubUser) -> T,
{
    let response = client.get(url.as_str()).send().await.map_err(|e| {
        Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("Failed to fetch GitHub user: {}", e),
        )
    })?;

    parse_github_user_response(response, context_label, transform).await
}

async fn parse_github_user_response<T, F>(
    response: reqwest::Response,
    context_label: &str,
    transform: F,
) -> Result<T>
where
    F: FnOnce(GitHubUser) -> T,
{
    let status = response.status();
    if !status.is_success() {
        return Err(Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!(
                "GitHub user not found for {} (status: {})",
                context_label, status
            ),
        ));
    }

    let user: GitHubUser = response.json().await.map_err(|e| {
        Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("Failed to parse GitHub user response: {}", e),
        )
    })?;

    Ok(transform(user))
}

/// Resolve a GitHub account id to `(id, current_login)` via REST API.
pub(crate) async fn fetch_github_user_by_id(
    client: &reqwest::Client,
    account_id: u64,
) -> Result<(u64, String)> {
    let url = build_github_user_by_id_url(account_id)?;
    fetch_github_user_by_id_with_url(client, account_id, url).await
}

fn build_github_user_by_id_url(account_id: u64) -> Result<reqwest::Url> {
    let account_id_segment = account_id.to_string();
    build_github_api_url(&["user", &account_id_segment])
}

async fn fetch_github_user_by_id_with_url(
    client: &reqwest::Client,
    account_id: u64,
    url: reqwest::Url,
) -> Result<(u64, String)> {
    let label = format!("account id '{}'", account_id);
    fetch_github_user_api(client, url, &label, |u| (u.id, u.login)).await
}

/// Fetch a GitHub user by login via REST API (GET /users/{login}).
pub(crate) async fn fetch_github_user_by_login(
    client: &reqwest::Client,
    login: &str,
) -> Result<GithubAccount> {
    validation::validate_github_login(login)?;
    let url = build_github_user_by_login_url(login)?;
    fetch_github_user_by_login_with_url(client, login, url).await
}

fn build_github_user_by_login_url(login: &str) -> Result<reqwest::Url> {
    build_github_api_url(&["users", login])
}

async fn fetch_github_user_by_login_with_url(
    client: &reqwest::Client,
    login: &str,
    url: reqwest::Url,
) -> Result<GithubAccount> {
    let label = format!("login '{}'", login);
    fetch_github_user_api(client, url, &label, |u| GithubAccount {
        id: u.id,
        login: u.login,
    })
    .await
}

/// Fetch SSH keys from GitHub REST API (GET /users/{login}/keys).
pub(crate) async fn fetch_github_keys(
    client: &reqwest::Client,
    login: &str,
) -> Result<Vec<GitHubKeyRecord>> {
    validation::validate_github_login(login)?;
    let url = build_github_keys_url(login)?;
    fetch_github_keys_with_url(client, url).await
}

fn build_github_keys_url(login: &str) -> Result<reqwest::Url> {
    build_github_api_url(&["users", login, "keys"])
}

async fn fetch_github_keys_with_url(
    client: &reqwest::Client,
    url: reqwest::Url,
) -> Result<Vec<GitHubKeyRecord>> {
    let response = client.get(url.as_str()).send().await.map_err(|e| {
        Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("Failed to fetch GitHub keys: {}", e),
        )
    })?;
    parse_github_keys(response).await
}

async fn parse_github_keys(response: reqwest::Response) -> Result<Vec<GitHubKeyRecord>> {
    if !response.status().is_success() {
        return Err(Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("GitHub API returned status: {}", response.status()),
        ));
    }

    let keys: Vec<GitHubKey> = response.json().await.map_err(|e| {
        Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("Failed to parse GitHub API response: {}", e),
        )
    })?;

    Ok(keys
        .into_iter()
        .map(|key| GitHubKeyRecord {
            id: key.id,
            key: key.key,
        })
        .collect())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_github_http_test.rs"]
mod tests;
