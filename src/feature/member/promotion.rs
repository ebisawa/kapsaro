// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member promotion - verify and promote incoming members to active status.

use std::path::Path;

use super::verification::build_verification_result_groups;
use crate::io::verify_online::VerificationResult;
use crate::io::workspace::members::promote_specified_incoming_members;
use crate::Result;

/// Result of incoming member online verification (before promotion).
pub struct IncomingVerificationReport {
    /// GitHub verification succeeded
    pub verified: Vec<VerificationResult>,
    /// Verification failed (API error, fingerprint mismatch)
    pub failed: Vec<VerificationResult>,
    /// GitHub not configured (no binding_claims.github_account)
    pub not_configured: Vec<VerificationResult>,
}

impl IncomingVerificationReport {
    /// Return member IDs from all categories.
    pub fn collect_member_ids(&self) -> Vec<String> {
        self.verified
            .iter()
            .chain(self.failed.iter())
            .chain(self.not_configured.iter())
            .map(|r| r.member_id.clone())
            .collect()
    }

    /// Return member IDs from verified category only.
    pub fn collect_verified_member_ids(&self) -> Vec<String> {
        self.verified.iter().map(|r| r.member_id.clone()).collect()
    }

    /// Return member IDs excluding online-verification-failed members.
    pub fn collect_promotable_member_ids(&self) -> Vec<String> {
        self.verified
            .iter()
            .chain(self.not_configured.iter())
            .map(|r| r.member_id.clone())
            .collect()
    }
}

/// Classify incoming verification results for promotion operations.
pub fn build_incoming_verification_report(
    results: &[VerificationResult],
) -> IncomingVerificationReport {
    let (verified, failed, not_configured) = build_verification_result_groups(results);

    IncomingVerificationReport {
        verified: verified.into_iter().cloned().collect(),
        failed: failed.into_iter().cloned().collect(),
        not_configured: not_configured.into_iter().cloned().collect(),
    }
}

/// Promote specified members from incoming to active.
pub fn promote_verified_members(workspace_path: &Path, member_ids: &[String]) -> Result<()> {
    if member_ids.is_empty() {
        return Ok(());
    }
    promote_specified_incoming_members(workspace_path, member_ids)?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_member_promotion_test.rs"]
mod tests;
