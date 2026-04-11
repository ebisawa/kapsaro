// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! HTTP transport helpers for GitHub verification.

use super::GitHubKeyRecord;
use crate::{Error, Result};
use serde::Deserialize;

/// GitHub API response for user keys
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

/// Build HTTP client for GitHub API requests
pub(super) fn build_http_client() -> Result<reqwest::Client> {
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

/// Resolve GitHub account ID to (id, current login) via REST API.
pub(super) async fn fetch_github_user_by_id(
    client: &reqwest::Client,
    account_id: u64,
) -> Result<(u64, String)> {
    let url = format!("https://api.github.com/user/{}", account_id);
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
                "GitHub user not found for account id '{}' (status: {})",
                account_id, status
            ),
        });
    }

    let user: GitHubUser = response.json().await.map_err(|e| Error::Verify {
        rule: "V-GITHUB-API".to_string(),
        message: format!("Failed to parse GitHub user response: {}", e),
    })?;

    Ok((user.id, user.login))
}

/// Fetch SSH keys from GitHub REST API (GET /users/{login}/keys).
pub(super) async fn fetch_github_keys(
    client: &reqwest::Client,
    login: &str,
) -> Result<Vec<GitHubKeyRecord>> {
    let url = format!("https://api.github.com/users/{}/keys", login);
    let request = build_github_request(client, &url);
    let response = request.send().await.map_err(|e| Error::Verify {
        rule: "V-GITHUB-API".to_string(),
        message: format!("Failed to fetch GitHub keys: {}", e),
    })?;
    parse_github_keys(response).await
}

async fn parse_github_keys(response: reqwest::Response) -> Result<Vec<GitHubKeyRecord>> {
    if !response.status().is_success() {
        return Err(Error::Verify {
            rule: "V-GITHUB-API".to_string(),
            message: format!("GitHub API returned status: {}", response.status()),
        });
    }

    let keys: Vec<GitHubKey> = response.json().await.map_err(|e| Error::Verify {
        rule: "V-GITHUB-API".to_string(),
        message: format!("Failed to parse GitHub API response: {}", e),
    })?;

    Ok(keys
        .into_iter()
        .map(|key| GitHubKeyRecord {
            id: key.id,
            key: key.key,
        })
        .collect())
}
