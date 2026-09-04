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
) -> Result<(u64, String)> {
    debug!(
        "[VERIFY] GitHub API: GET https://api.github.com/user/{}",
        document_id
    );

    let (id_from_api, login_from_api) = api.fetch_user_by_id(document_id).await?;
    debug!(
        "[VERIFY] GitHub API: user id={}, login={} (document id={})",
        id_from_api, login_from_api, document_id
    );

    if id_from_api != document_id {
        return Err(Error::build_verification_error(
            "V-GITHUB-API".to_string(),
            format!(
                "GitHub user id mismatch: document id {} vs API id {}",
                document_id, id_from_api
            ),
        ));
    }

    Ok((id_from_api, login_from_api))
}

pub(super) async fn verify_github_keys(
    api: &impl GitHubVerificationApi,
    public_key: &PublicKey,
    our_fingerprint: &str,
    id_used: u64,
    login_for_keys: &str,
) -> Result<VerificationResult> {
    let member_handle = &public_key.protected.subject_handle;
    debug!("[VERIFY] GitHub API: GET https://api.github.com/users/{login_for_keys}/keys");

    let github_keys = api.fetch_keys(login_for_keys).await?;
    let key_count = github_keys.len();
    debug!("[VERIFY] GitHub API: fetched {key_count} key(s)");

    if github_keys.is_empty() {
        return Ok(build_no_listed_keys_result(member_handle, id_used));
    }
    if let Some(result) = find_key_by_fingerprint(
        public_key,
        our_fingerprint,
        &github_keys,
        id_used,
        login_for_keys,
    ) {
        return Ok(result);
    }

    debug!("[VERIFY] Verify {member_handle}: no matching key among {key_count} key(s)");
    Ok(build_key_not_listed_result(
        member_handle,
        our_fingerprint,
        id_used,
        key_count,
    ))
}

/// Report an account that lists no SSH key at all.
///
/// No fingerprint is carried: nothing was compared against ours, so naming one
/// would suggest a comparison that never happened.
fn build_no_listed_keys_result(member_handle: &str, id_used: u64) -> VerificationResult {
    VerificationResult::failed(
        member_handle,
        format!("No SSH keys found for GitHub user id {}", id_used),
        None,
        true,
    )
}

/// Report an account whose listed keys do not include ours.
///
/// The count says how much was checked, so the reader can tell this from an
/// account that listed nothing.
fn build_key_not_listed_result(
    member_handle: &str,
    our_fingerprint: &str,
    id_used: u64,
    checked_keys: usize,
) -> VerificationResult {
    VerificationResult::failed(
        member_handle,
        format!(
            "SSH key not found on GitHub (id={}, checked {} keys)",
            id_used, checked_keys
        ),
        Some(our_fingerprint.to_string()),
        true,
    )
}
