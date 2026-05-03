// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verification policy helpers for GitHub binding checks.

use super::{matcher::find_key_by_fingerprint, GitHubVerificationApi};
use crate::io::verify_online::VerificationResult;
use crate::model::public_key::PublicKey;
use crate::{Error, Result};
use tracing::debug;

pub(super) async fn resolve_github_identity(
    api: &impl GitHubVerificationApi,
    document_id: u64,
    known: &Option<(u64, String)>,
    member_handle: &str,
    verbose: bool,
) -> Result<(u64, String)> {
    match known {
        Some((id_known, login_known)) => {
            if *id_known != document_id {
                return Err(Error::Verify {
                    rule: "V-GITHUB-API".to_string(),
                    message: format!(
                        "GitHub user id mismatch: document id {} vs provided id {}",
                        document_id, id_known
                    ),
                });
            }
            if verbose {
                debug!(
                    "[VERIFY] Verify {}: using known github id/current login (skip GET /user/{{id}})",
                    member_handle
                );
            }
            Ok((*id_known, login_known.clone()))
        }
        None => resolve_github_identity_from_api(api, document_id, member_handle, verbose).await,
    }
}

async fn resolve_github_identity_from_api(
    api: &impl GitHubVerificationApi,
    document_id: u64,
    _member_handle: &str,
    verbose: bool,
) -> Result<(u64, String)> {
    if verbose {
        debug!(
            "[VERIFY] GitHub API: GET https://api.github.com/user/{}",
            document_id
        );
    }

    let (id_from_api, login_from_api) = api.fetch_user_by_id(document_id).await?;
    if verbose {
        debug!(
            "[VERIFY] GitHub API: user id={}, login={} (document id={})",
            id_from_api, login_from_api, document_id
        );
    }

    if id_from_api != document_id {
        return Err(Error::Verify {
            rule: "V-GITHUB-API".to_string(),
            message: format!(
                "GitHub user id mismatch: document id {} vs API id {}",
                document_id, id_from_api
            ),
        });
    }

    Ok((id_from_api, login_from_api))
}

pub(super) async fn verify_github_keys(
    api: &impl GitHubVerificationApi,
    public_key: &PublicKey,
    our_fingerprint: &str,
    id_used: u64,
    login_for_keys: &str,
    verbose: bool,
) -> Result<VerificationResult> {
    let member_handle = &public_key.protected.subject_handle;

    if verbose {
        debug!(
            "[VERIFY] GitHub API: GET https://api.github.com/users/{}/keys",
            login_for_keys
        );
    }

    let github_keys = api.fetch_keys(login_for_keys).await?;
    if verbose {
        debug!("[VERIFY] GitHub API: fetched {} key(s)", github_keys.len());
    }

    if github_keys.is_empty() {
        return Ok(VerificationResult::failed(
            member_handle,
            format!("No SSH keys found for GitHub user id {}", id_used),
            None,
            true,
        ));
    }

    if let Some(result) = find_key_by_fingerprint(
        public_key,
        our_fingerprint,
        &github_keys,
        id_used,
        login_for_keys,
        verbose,
    ) {
        return Ok(result);
    }

    if verbose {
        debug!(
            "[VERIFY] Verify {}: no matching key among {} key(s)",
            member_handle,
            github_keys.len()
        );
    }

    Ok(VerificationResult::failed(
        member_handle,
        format!(
            "SSH key not found on GitHub (id={}, checked {} keys)",
            id_used,
            github_keys.len()
        ),
        Some(our_fingerprint.to_string()),
        true,
    ))
}
