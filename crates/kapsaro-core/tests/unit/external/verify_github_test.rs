// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for GitHub binding_claims.github_account verification.

use kapsaro_core::cli_api::test_support::domain::public_key::{
    Attestation, BindingClaims, GithubAccount, IdentityKeys, JwkOkpPublicKey, PublicKey,
    PublicKeyProtected,
};
use kapsaro_core::cli_api::test_support::storage::github::http::GitHubKeyRecord;
use kapsaro_core::cli_api::test_support::storage::verify_online::github::{
    verify_github_account_with_api, GitHubApiFuture, GitHubVerificationApi,
};
use kapsaro_core::cli_api::test_support::storage::verify_online::{
    VerificationStatus, VerifiedGithubIdentity,
};
use kapsaro_core::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const TEST_SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";

struct FakeGitHubApi {
    user_by_id_result: Result<(u64, String)>,
    keys_result: Result<Vec<GitHubKeyRecord>>,
}

impl GitHubVerificationApi for FakeGitHubApi {
    fn fetch_user_by_id<'a>(&'a self, _account_id: u64) -> GitHubApiFuture<'a, (u64, String)> {
        Box::pin(async move {
            match &self.user_by_id_result {
                Ok((id, login)) => Ok((*id, login.clone())),
                Err(error) if error.kind() == ErrorKind::Verify => {
                    Err(Error::build_verification_error(
                        error.verification_rule().expect("verification rule"),
                        error.format_user_message(),
                    ))
                }
                Err(other) => Err(Error::build_verification_error(
                    "V-GITHUB-API".to_string(),
                    other.to_string(),
                )),
            }
        })
    }

    fn fetch_keys<'a>(&'a self, _login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>> {
        Box::pin(async move {
            match &self.keys_result {
                Ok(keys) => Ok(keys.clone()),
                Err(error) if error.kind() == ErrorKind::Verify => {
                    Err(Error::build_verification_error(
                        error.verification_rule().expect("verification rule"),
                        error.format_user_message(),
                    ))
                }
                Err(other) => Err(Error::build_verification_error(
                    "V-GITHUB-API".to_string(),
                    other.to_string(),
                )),
            }
        })
    }
}

struct RecordingGitHubApi {
    user_by_id_result: Result<(u64, String)>,
    keys_result: Result<Vec<GitHubKeyRecord>>,
    user_calls: Arc<AtomicUsize>,
    key_calls: Arc<AtomicUsize>,
    last_keys_login: Arc<Mutex<Option<String>>>,
}

impl RecordingGitHubApi {
    fn new(
        user_by_id_result: Result<(u64, String)>,
        keys_result: Result<Vec<GitHubKeyRecord>>,
    ) -> Self {
        Self {
            user_by_id_result,
            keys_result,
            user_calls: Arc::new(AtomicUsize::new(0)),
            key_calls: Arc::new(AtomicUsize::new(0)),
            last_keys_login: Arc::new(Mutex::new(None)),
        }
    }

    fn user_call_count(&self) -> usize {
        self.user_calls.load(Ordering::SeqCst)
    }

    fn key_call_count(&self) -> usize {
        self.key_calls.load(Ordering::SeqCst)
    }

    fn last_keys_login(&self) -> Option<String> {
        self.last_keys_login.lock().unwrap().clone()
    }
}

impl GitHubVerificationApi for RecordingGitHubApi {
    fn fetch_user_by_id<'a>(&'a self, _account_id: u64) -> GitHubApiFuture<'a, (u64, String)> {
        Box::pin(async move {
            self.user_calls.fetch_add(1, Ordering::SeqCst);
            match &self.user_by_id_result {
                Ok((id, login)) => Ok((*id, login.clone())),
                Err(error) if error.kind() == ErrorKind::Verify => {
                    Err(Error::build_verification_error(
                        error.verification_rule().expect("verification rule"),
                        error.format_user_message(),
                    ))
                }
                Err(other) => Err(Error::build_verification_error(
                    "V-GITHUB-API".to_string(),
                    other.to_string(),
                )),
            }
        })
    }

    fn fetch_keys<'a>(&'a self, login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>> {
        Box::pin(async move {
            self.key_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_keys_login.lock().unwrap() = Some(login.to_string());
            match &self.keys_result {
                Ok(keys) => Ok(keys.clone()),
                Err(error) if error.kind() == ErrorKind::Verify => {
                    Err(Error::build_verification_error(
                        error.verification_rule().expect("verification rule"),
                        error.format_user_message(),
                    ))
                }
                Err(other) => Err(Error::build_verification_error(
                    "V-GITHUB-API".to_string(),
                    other.to_string(),
                )),
            }
        })
    }
}

fn sample_public_key() -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: "kapsaro:format:public-key@1".to_string(),
            subject_handle: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "X25519".to_string(),
                    x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                },
            },
            attestation: Attestation {
                method: "ssh".to_string(),
                pub_: TEST_SSH_PUBKEY.to_string(),
                sig: "signature".to_string(),
            },
            binding_claims: Some(BindingClaims {
                github_account: Some(GithubAccount {
                    id: 42,
                    login: "alice".to_string(),
                }),
            }),
            expires_at: "2099-12-31T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "sig".to_string(),
    }
}

#[tokio::test]
async fn test_verify_github_account_with_fake_api() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((42, "alice".to_string())),
        keys_result: Ok(vec![GitHubKeyRecord {
            id: 100,
            key: TEST_SSH_PUBKEY.to_string(),
        }]),
    };

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert!(result.is_verified());
    assert_eq!(result.matched_key_id, Some(100));
    assert_eq!(
        result
            .verified_github
            .as_ref()
            .expect("verified github")
            .matched_key_id,
        100
    );
}

#[tokio::test]
async fn test_verify_github_account_rejects_id_mismatch() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((7, "alice".to_string())),
        keys_result: Ok(Vec::new()),
    };

    let result = verify_github_account_with_api(&public_key, false, &api).await;

    let error = result.expect_err("expected verify error");
    assert_eq!(error.kind(), ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("V-GITHUB-API"));
    assert!(
        error
            .format_user_message()
            .contains("document id 42 vs API id 7"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[tokio::test]
async fn test_verify_github_account_reports_empty_github_keys() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((42, "alice".to_string())),
        keys_result: Ok(Vec::new()),
    };

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert_eq!(result.status, VerificationStatus::Failed);
    assert_eq!(result.message, "No SSH keys found for GitHub user id 42");
    assert_eq!(result.matched_key_id, None);
    assert!(result.verified_github.is_none());
}

#[tokio::test]
async fn test_verify_github_account_propagates_keys_api_error() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((42, "alice".to_string())),
        keys_result: Err(Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            "keys endpoint failed".to_string(),
        )),
    };

    let result = verify_github_account_with_api(&public_key, false, &api).await;

    let error = result.expect_err("expected verify error");
    assert_eq!(error.kind(), ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("V-GITHUB-API"));
    assert_eq!(error.format_user_message(), "keys endpoint failed");
}

#[tokio::test]
async fn test_verify_github_account_skips_malformed_key_records_before_match() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((42, "alice".to_string())),
        keys_result: Ok(vec![
            GitHubKeyRecord {
                id: 99,
                key: "not an ssh key".to_string(),
            },
            GitHubKeyRecord {
                id: 100,
                key: TEST_SSH_PUBKEY.to_string(),
            },
        ]),
    };

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert!(result.is_verified());
    assert_eq!(result.matched_key_id, Some(100));
}

#[tokio::test]
async fn test_verify_github_account_reports_missing_key_when_all_records_are_malformed() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((42, "alice".to_string())),
        keys_result: Ok(vec![
            GitHubKeyRecord {
                id: 99,
                key: "not an ssh key".to_string(),
            },
            GitHubKeyRecord {
                id: 100,
                key: "also not an ssh key".to_string(),
            },
        ]),
    };

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert_eq!(result.status, VerificationStatus::Failed);
    assert_eq!(result.matched_key_id, None);
    assert!(result.message.contains("SSH key not found on GitHub"));
    assert!(result.verified_github.is_none());
}

#[tokio::test]
async fn test_verify_github_account_reports_missing_matching_key() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((42, "alice".to_string())),
        keys_result: Ok(vec![GitHubKeyRecord {
            id: 200,
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other@example.com".to_string(),
        }]),
    };

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert!(!result.is_verified());
    assert_eq!(result.matched_key_id, None);
}

#[tokio::test]
async fn test_verify_github_account_reports_not_configured_without_binding_claims() {
    let mut public_key = sample_public_key();
    public_key.protected.binding_claims = None;
    let api = RecordingGitHubApi::new(Ok((42, "alice".to_string())), Ok(Vec::new()));

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert_eq!(result.status, VerificationStatus::NotConfigured);
    assert_eq!(
        result.message,
        "No binding_claims.github_account configured"
    );
    assert_eq!(api.user_call_count(), 0);
    assert_eq!(api.key_call_count(), 0);
}

#[tokio::test]
async fn test_verify_github_account_reports_not_configured_without_github_account_claim() {
    let mut public_key = sample_public_key();
    public_key.protected.binding_claims = Some(BindingClaims {
        github_account: None,
    });
    let api = RecordingGitHubApi::new(Ok((42, "alice".to_string())), Ok(Vec::new()));

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert_eq!(result.status, VerificationStatus::NotConfigured);
    assert!(!result.github_claim_present);
    assert_eq!(
        result.message,
        "No binding_claims.github_account configured"
    );
    assert_eq!(api.user_call_count(), 0);
    assert_eq!(api.key_call_count(), 0);
}

#[tokio::test]
async fn test_verify_github_account_reports_not_configured_for_invalid_attestation() {
    let mut public_key = sample_public_key();
    public_key.protected.attestation.pub_ = "invalid-ssh-key".to_string();
    let api = FakeGitHubApi {
        user_by_id_result: Ok((42, "alice".to_string())),
        keys_result: Ok(Vec::new()),
    };

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    assert_eq!(result.status, VerificationStatus::Failed);
    assert_eq!(
        result.message,
        "Invalid attestation.pub (cannot compute fingerprint)"
    );
}

#[tokio::test]
async fn test_verify_github_account_uses_document_id_and_current_login() {
    let mut public_key = sample_public_key();
    public_key
        .protected
        .binding_claims
        .as_mut()
        .unwrap()
        .github_account
        .as_mut()
        .unwrap()
        .login = "stale-login".to_string();
    let api = RecordingGitHubApi::new(
        Ok((42, "alice-current".to_string())),
        Ok(vec![GitHubKeyRecord {
            id: 100,
            key: TEST_SSH_PUBKEY.to_string(),
        }]),
    );

    let result = verify_github_account_with_api(&public_key, false, &api)
        .await
        .unwrap();

    let verified = result.verified_github.as_ref().expect("verified github");
    assert_eq!(verified.id, 42);
    assert_eq!(verified.login, "alice-current");
    assert_eq!(
        result.message,
        "SSH key verified on GitHub (id=42, login=alice-current)"
    );
    assert_eq!(api.user_call_count(), 1);
    assert_eq!(api.key_call_count(), 1);
    assert_eq!(api.last_keys_login().as_deref(), Some("alice-current"));
}

#[test]
fn test_github_account_structure_github_has_id_and_login() {
    let github = GithubAccount {
        id: 12345,
        login: "alice".to_string(),
    };
    assert_eq!(github.id, 12345);
    assert_eq!(github.login, "alice");
}

#[test]
fn test_verification_result_verified_github_some() {
    use kapsaro_core::cli_api::test_support::storage::verify_online::{
        VerificationResult, VerificationStatus,
    };
    let verified_github =
        VerifiedGithubIdentity::new(99, "bob".to_string(), "SHA256:fp".to_string(), 100);

    let result = VerificationResult {
        member_handle: "bob@example.com".to_string(),
        status: VerificationStatus::Verified,
        message: "SSH key verified on GitHub".to_string(),
        fingerprint: Some("SHA256:fp".to_string()),
        matched_key_id: Some(100),
        github_claim_present: true,
        verified_github: Some(verified_github),
    };

    assert!(result.is_verified());
    let github = result.verified_github.as_ref().expect("verified_github");
    assert_eq!(github.login, "bob");
    assert_eq!(github.matched_key_id, 100);
}
