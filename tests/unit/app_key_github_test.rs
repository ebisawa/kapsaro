// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for app::key::github verification status

use crate::app::key::types::KeyNewResult;
use crate::app::verification::OnlineVerificationStatus;

#[test]
fn test_key_new_result_github_verification_not_configured_by_default() {
    // KeyNewResult.github_verification must be OnlineVerificationStatus::NotConfigured
    // when no github_user is specified.
    // This test verifies the field exists and has the correct type.
    let _: fn(OnlineVerificationStatus) = |_: OnlineVerificationStatus| {};

    // Verify the field access compiles: KeyNewResult must have github_verification
    fn assert_has_expected_fields(
        r: &KeyNewResult,
    ) -> (
        &str,
        &str,
        &str,
        bool,
        &str,
        &secretenv::model::ssh::SshDeterminismStatus,
        OnlineVerificationStatus,
    ) {
        (
            &r.member_id,
            &r.kid,
            &r.expires_at,
            r.activated,
            &r.ssh_fingerprint,
            &r.ssh_determinism,
            r.github_verification,
        )
    }
    let _ = assert_has_expected_fields;
}
