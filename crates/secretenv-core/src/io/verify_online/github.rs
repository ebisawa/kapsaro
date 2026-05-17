// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! GitHub verification logic
//!
//! Verification uses binding_claims.github_account.id as the primary key:
//! GET /user/{id} to resolve the current login, then GET /users/{login}/keys.
//! REST only, no authentication required.

use crate::io::github::http::{
    build_http_client, fetch_github_keys, fetch_github_user_by_id, GitHubKeyRecord,
};
use crate::model::public_key::PublicKey;
use crate::Result;
use std::future::Future;
use std::pin::Pin;
use tracing::debug;

use self::matcher::compute_attestation_fingerprint;
use self::policy::{resolve_github_identity, verify_github_keys};
use super::VerificationResult;

mod matcher;
mod policy;
pub mod preflight;

/// Boxed future used by GitHub API abstractions.
pub type GitHubApiFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Injectable GitHub API interface used by verification checks.
pub trait GitHubVerificationApi {
    fn fetch_user_by_id<'a>(&'a self, account_id: u64) -> GitHubApiFuture<'a, (u64, String)>;
    fn fetch_keys<'a>(&'a self, login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>>;
}

pub(super) struct GitHubVerificationApiClient {
    client: reqwest::Client,
}

impl GitHubVerificationApiClient {
    fn new() -> Result<Self> {
        Ok(Self {
            client: build_http_client()?,
        })
    }
}

impl GitHubVerificationApi for GitHubVerificationApiClient {
    fn fetch_user_by_id<'a>(&'a self, account_id: u64) -> GitHubApiFuture<'a, (u64, String)> {
        Box::pin(async move { fetch_github_user_by_id(&self.client, account_id).await })
    }

    fn fetch_keys<'a>(&'a self, login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>> {
        Box::pin(async move { fetch_github_keys(&self.client, login).await })
    }
}

/// Verify a PublicKey's binding_claims.github_account against GitHub using REST only
/// (id -> current login -> keys).
/// When `known_github_account` is `Some((id, login))`, skips GET /user/{id}` and uses the given
/// current login for keys fetch.
pub async fn verify_github_account(
    public_key: &PublicKey,
    verbose: bool,
    known_github_account: Option<(u64, String)>,
) -> Result<VerificationResult> {
    let api = GitHubVerificationApiClient::new()?;
    verify_github_account_with_api(public_key, verbose, known_github_account, &api).await
}

/// Verify a PublicKey's GitHub binding using an injected API implementation.
pub async fn verify_github_account_with_api(
    public_key: &PublicKey,
    verbose: bool,
    known_github_account: Option<(u64, String)>,
    api: &impl GitHubVerificationApi,
) -> Result<VerificationResult> {
    let member_handle = &public_key.protected.subject_handle;
    let github = match public_key
        .protected
        .binding_claims
        .as_ref()
        .and_then(|b| b.github_account.as_ref())
    {
        Some(b) => b,
        None => {
            if verbose {
                debug!(
                    "[VERIFY] Verify {}: no binding_claims.github_account configured (skipped)",
                    member_handle
                );
            }
            let fingerprint = compute_attestation_fingerprint(public_key, verbose);
            return Ok(VerificationResult::not_configured(
                member_handle,
                "No binding_claims.github_account configured",
                fingerprint,
                false,
            ));
        }
    };

    let our_fingerprint = match compute_attestation_fingerprint(public_key, verbose) {
        Some(fp) => fp,
        None => {
            return Ok(VerificationResult::failed(
                member_handle,
                "Invalid attestation.pub (cannot compute fingerprint)".to_string(),
                None,
                true,
            ));
        }
    };

    let (id_used, login_for_keys) = resolve_github_identity(
        api,
        github.id,
        &known_github_account,
        member_handle,
        verbose,
    )
    .await?;

    verify_github_keys(
        api,
        public_key,
        &our_fingerprint,
        id_used,
        &login_for_keys,
        verbose,
    )
    .await
}
