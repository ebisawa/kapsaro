// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! HTTP transport helpers for GitHub REST API access.
//!
//! Shared between pre-flight key verification, online verification, and
//! key-generation account lookup.

use crate::model::public_key::GithubAccount;
use crate::support::limits::MAX_GITHUB_RESPONSE_SIZE;
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
///
/// Redirects are refused: the API does not redirect on the paths used here, so
/// following one would only serve to move the request to another host.
pub(crate) fn build_http_client() -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .user_agent(format!("kapsaro/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(github_api_headers());

    builder
        .build()
        .map_err(|e| Error::build_config_error(format!("Failed to create HTTP client: {}", e)))
}

/// Pin the response shape to a documented API version.
fn github_api_headers() -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};

    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        HeaderName::from_static("x-github-api-version"),
        HeaderValue::from_static("2022-11-28"),
    );
    headers
}

/// Turn a rate limit response into a message that names the cause.
///
/// Unauthenticated callers share a low hourly quota, and a bare status code
/// gives no hint that waiting is the remedy.
fn rate_limit_error(response: &reqwest::Response) -> Option<Error> {
    let status = response.status();
    if status != reqwest::StatusCode::TOO_MANY_REQUESTS
        && !(status == reqwest::StatusCode::FORBIDDEN && exhausted_rate_limit(response))
    {
        return None;
    }

    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(|value| format!(" Retry after {} seconds.", value))
        .unwrap_or_default();
    Some(Error::build_verification_error(
        "V-GITHUB-API".to_string(),
        format!(
            "GitHub API rate limit reached (status: {}).{} Unauthenticated \
             requests share a low hourly quota.",
            status, retry_after
        ),
    ))
}

fn exhausted_rate_limit(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "0")
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
    if let Some(error) = rate_limit_error(&response) {
        return Err(error);
    }
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

    let user: GitHubUser = read_capped_json(response, "GitHub user response").await?;
    Ok(transform(user))
}

/// Read a bounded response body and deserialize it.
///
/// `Response::json` reads to the end with no ceiling, so the peer decides how
/// much is allocated.
async fn read_capped_json<T>(response: reqwest::Response, subject: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let body = read_capped_body(response, subject).await?;
    serde_json::from_slice(&body).map_err(|e| {
        Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("Failed to parse {}: {}", subject, e),
        )
    })
}

async fn read_capped_body(mut response: reqwest::Response, subject: &str) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("Failed to read {}: {}", subject, e),
        )
    })? {
        if body.len() + chunk.len() > MAX_GITHUB_RESPONSE_SIZE {
            return Err(Error::build_verification_error(
                "V-GITHUB-API".to_string(),
                format!(
                    "{} exceeds the maximum size of {} bytes",
                    subject, MAX_GITHUB_RESPONSE_SIZE
                ),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
    if let Some(error) = rate_limit_error(&response) {
        return Err(error);
    }
    if !response.status().is_success() {
        return Err(Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!("GitHub API returned status: {}", response.status()),
        ));
    }

    let keys: Vec<GitHubKey> = read_capped_json(response, "GitHub keys response").await?;

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
