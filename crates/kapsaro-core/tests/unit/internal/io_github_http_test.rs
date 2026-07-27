// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    build_github_api_url_from_base, build_github_keys_url, build_github_user_by_id_url,
    build_github_user_by_login_url, build_http_client, fetch_github_keys,
    fetch_github_user_by_login, parse_github_keys, parse_github_user_response, GitHubKeyRecord,
};
use crate::model::public_key::GithubAccount;
use crate::Error;
use reqwest::ResponseBuilderExt;

fn response(status: u16, body: &'static str) -> reqwest::Response {
    http::Response::builder()
        .status(status)
        .url(reqwest::Url::parse("http://example.test/response").unwrap())
        .body(body)
        .unwrap()
        .into()
}

fn rate_limited_response(status: u16) -> reqwest::Response {
    http::Response::builder()
        .status(status)
        .header("x-ratelimit-remaining", "0")
        .header("retry-after", "60")
        .url(reqwest::Url::parse("http://example.test/response").unwrap())
        .body("")
        .unwrap()
        .into()
}

fn oversized_body() -> reqwest::Response {
    let body = "a".repeat(crate::support::limits::MAX_GITHUB_RESPONSE_SIZE + 1);
    http::Response::builder()
        .status(200)
        .url(reqwest::Url::parse("http://example.test/response").unwrap())
        .body(body)
        .unwrap()
        .into()
}

/// A bare status code gives no hint that the quota is the cause, and the
/// unauthenticated quota is small enough to hit during normal use.
#[tokio::test]
async fn test_parse_github_keys_reports_an_exhausted_rate_limit() {
    let error = parse_github_keys(rate_limited_response(403))
        .await
        .unwrap_err();

    let message = error.format_user_message();
    assert!(message.contains("rate limit"), "unexpected: {message}");
    assert!(message.contains("60"), "unexpected: {message}");
}

#[tokio::test]
async fn test_parse_github_keys_reports_too_many_requests() {
    let error = parse_github_keys(rate_limited_response(429))
        .await
        .unwrap_err();

    assert!(
        error.format_user_message().contains("rate limit"),
        "unexpected: {}",
        error.format_user_message()
    );
}

/// The response body is peer-controlled, so its size decides how much is
/// allocated unless the read is bounded.
#[tokio::test]
async fn test_parse_github_keys_rejects_an_oversized_body() {
    let error = parse_github_keys(oversized_body()).await.unwrap_err();

    assert!(
        error.format_user_message().contains("maximum size"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[test]
fn test_build_github_api_url_from_base_extends_path_segments() {
    let base = reqwest::Url::parse("http://example.test").unwrap();

    let url = build_github_api_url_from_base(base, &["users", "alice", "keys"]).unwrap();

    assert_eq!(url.as_str(), "http://example.test/users/alice/keys");
}

#[test]
fn test_github_endpoint_builders_keep_rest_paths_stable() {
    assert_eq!(
        build_github_user_by_id_url(42).unwrap().as_str(),
        "https://api.github.com/user/42"
    );
    assert_eq!(
        build_github_user_by_login_url("alice").unwrap().as_str(),
        "https://api.github.com/users/alice"
    );
    assert_eq!(
        build_github_keys_url("alice").unwrap().as_str(),
        "https://api.github.com/users/alice/keys"
    );
}

#[tokio::test]
async fn test_parse_github_user_response_for_login() {
    let account = parse_github_user_response(
        response(200, r#"{"id":42,"login":"alice"}"#),
        "login 'alice'",
        |user| GithubAccount {
            id: user.id,
            login: user.login,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        account,
        GithubAccount {
            id: 42,
            login: "alice".to_string()
        }
    );
}

#[tokio::test]
async fn test_parse_github_user_response_for_account_id() {
    let account = parse_github_user_response(
        response(200, r#"{"id":42,"login":"alice-renamed"}"#),
        "account id '42'",
        |user| (user.id, user.login),
    )
    .await
    .unwrap();

    assert_eq!(account, (42, "alice-renamed".to_string()));
}

#[tokio::test]
async fn test_parse_github_user_response_non_success_error() {
    let error = parse_github_user_response(
        response(404, r#"{"message":"Not Found"}"#),
        "login 'alice'",
        |user| GithubAccount {
            id: user.id,
            login: user.login,
        },
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("V-GITHUB-API"));
    assert!(
        error
            .format_user_message()
            .contains("GitHub user not found for login 'alice'"),
        "unexpected: {}",
        error.format_user_message()
    );
    assert!(
        error.format_user_message().contains("404 Not Found"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[tokio::test]
async fn test_parse_github_user_response_invalid_json_error() {
    let error = parse_github_user_response(
        response(200, r#"{"id":"not-a-number"}"#),
        "login 'alice'",
        |user| GithubAccount {
            id: user.id,
            login: user.login,
        },
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("V-GITHUB-API"));
    assert!(
        error
            .format_user_message()
            .contains("Failed to parse GitHub user response"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[tokio::test]
async fn test_parse_github_keys_response() {
    let body = r#"[{"id":100,"key":"ssh-ed25519 AAAA alice@example.com"}]"#;

    let keys = parse_github_keys(response(200, body)).await.unwrap();

    assert_eq!(
        keys,
        vec![GitHubKeyRecord {
            id: 100,
            key: "ssh-ed25519 AAAA alice@example.com".to_string()
        }]
    );
}

#[tokio::test]
async fn test_parse_github_keys_response_non_success_error() {
    let error = parse_github_keys(response(404, r#"{"message":"Not Found"}"#))
        .await
        .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("V-GITHUB-API"));
    assert!(
        error.format_user_message().contains("404 Not Found"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[tokio::test]
async fn test_parse_github_keys_response_invalid_json_error() {
    let error = parse_github_keys(response(200, r#"{"id":100}"#))
        .await
        .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("V-GITHUB-API"));
    assert!(
        error
            .format_user_message()
            .contains("Failed to parse GitHub keys response"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[tokio::test]
async fn test_fetch_github_user_by_login_rejects_invalid_login_before_transport() {
    let client = build_http_client().unwrap();

    let error = fetch_github_user_by_login(&client, "../alice")
        .await
        .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
    assert!(
        error.format_user_message().contains("GitHub login"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[tokio::test]
async fn test_fetch_github_keys_rejects_invalid_login_before_transport() {
    let client = build_http_client().unwrap();

    let error = fetch_github_keys(&client, "alice/bob").await.unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
    assert!(
        error.format_user_message().contains("GitHub login"),
        "unexpected: {}",
        error.format_user_message()
    );
}
