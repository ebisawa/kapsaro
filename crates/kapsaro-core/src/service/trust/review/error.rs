// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error builders for rejected trust approvals during review.
//! Centralizes the wording so approval, non-member, and rewrap rejections stay consistent.

use crate::service::trust::TrustApprovalCandidate;
use crate::Error;

pub(super) fn build_trust_approval_rejection_error(
    approval_subject: &str,
    reviewed: &TrustApprovalCandidate,
) -> Error {
    Error::build_verification_error(
        "E_TRUST_REJECTED".to_string(),
        format!(
            "Trust approval rejected for {} '{}' ({})",
            approval_subject,
            reviewed.member_handle(),
            reviewed.kid()
        ),
    )
}

pub(super) fn build_non_member_rejection_error(
    approval_subject: &str,
    reviewed: &TrustApprovalCandidate,
) -> Error {
    Error::build_verification_error(
        "E_TRUST_REJECTED".to_string(),
        format!(
            "Non-member acceptance rejected for {} '{}' ({})",
            approval_subject,
            reviewed.member_handle(),
            reviewed.kid()
        ),
    )
}
