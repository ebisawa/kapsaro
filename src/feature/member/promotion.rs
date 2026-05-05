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
    /// Return member handles from all categories.
    pub fn collect_member_handles(&self) -> Vec<String> {
        self.verified
            .iter()
            .chain(self.failed.iter())
            .chain(self.not_configured.iter())
            .map(|r| r.member_handle.clone())
            .collect()
    }

    /// Return member handles from verified category only.
    pub fn collect_verified_member_handles(&self) -> Vec<String> {
        self.verified
            .iter()
            .map(|r| r.member_handle.clone())
            .collect()
    }

    /// Return member handles excluding online-verification-failed members.
    pub fn collect_promotable_member_handles(&self) -> Vec<String> {
        self.verified
            .iter()
            .chain(self.not_configured.iter())
            .map(|r| r.member_handle.clone())
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
pub fn promote_verified_members(workspace_path: &Path, member_handles: &[String]) -> Result<()> {
    if member_handles.is_empty() {
        return Ok(());
    }
    promote_specified_incoming_members(workspace_path, member_handles)?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_member_promotion_test.rs"]
mod tests;
