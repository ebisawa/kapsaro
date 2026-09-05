// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the shared CLI read review loop helpers.
//! Fixes the review-failure rule and the per-artifact wording both read paths share.

use super::*;
use kapsaro_core::ErrorKind;

#[test]
fn test_file_review_target_change_reports_file_artifact_message() {
    let error = build_target_changed_error(ReadArtifactKind::File);

    assert_eq!(error.kind(), ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
    assert_eq!(
        error.format_user_message(),
        "Trust state changed while reviewing the file artifact"
    );
}

#[test]
fn test_kv_review_target_change_reports_kv_artifact_message() {
    let error = build_target_changed_error(ReadArtifactKind::Kv);

    assert_eq!(error.kind(), ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
    assert_eq!(
        error.format_user_message(),
        "Trust state changed while reviewing the KV artifact"
    );
}
