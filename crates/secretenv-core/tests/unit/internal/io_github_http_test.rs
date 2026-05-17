// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    build_github_api_url_from_base, build_github_keys_url, build_github_request,
    build_github_user_by_id_url, build_github_user_by_login_url, build_http_client,
    fetch_github_keys, fetch_github_user_by_login, parse_github_keys, parse_github_user_response,
    GitHubKeyRecord,
};
use crate::model::public_key::GithubAccount;
use crate::test_utils::EnvGuard;
use crate::Error;
use reqwest::ResponseBuilderExt;
use serial_test::serial;

fn response(status: u16, body: &'static str) -> reqwest::Response {
    http::Response::builder()
        .status(status)
        .url(reqwest::Url::parse("http://example.test/response").unwrap())
        .body(body)
        .unwrap()
        .into()
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
            .contains("Failed to parse GitHub API response"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[test]
#[serial]
fn test_build_github_request_sends_github_token() {
    let _guard = EnvGuard::new(&["GITHUB_TOKEN"]);
    std::env::set_var("GITHUB_TOKEN", "test-token");
    let client = build_http_client().unwrap();

    let request = build_github_request(&client, "http://example.test")
        .build()
        .unwrap();

    assert_eq!(
        request.headers().get("Authorization").unwrap(),
        "Bearer test-token"
    );
}

#[test]
#[serial]
fn test_build_github_request_omits_auth_header_without_github_token() {
    let _guard = EnvGuard::new(&["GITHUB_TOKEN"]);
    std::env::remove_var("GITHUB_TOKEN");
    let client = build_http_client().unwrap();

    let request = build_github_request(&client, "http://example.test")
        .build()
        .unwrap();

    assert!(request.headers().get("Authorization").is_none());
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
