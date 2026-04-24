// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::trust::TrustApprovalCandidate;
use crate::support::path::format_path_relative_to_cwd;
use crate::Error;

pub(super) fn build_trust_approval_rejection_error(
    approval_subject: &str,
    reviewed: &TrustApprovalCandidate,
) -> Error {
    Error::Verify {
        rule: "E_TRUST_APPROVAL_REJECTED".to_string(),
        message: format!(
            "Trust approval rejected for {} '{}' ({})",
            approval_subject, reviewed.member_id, reviewed.kid
        ),
    }
}

pub(super) fn build_non_member_rejection_error(
    approval_subject: &str,
    reviewed: &TrustApprovalCandidate,
) -> Error {
    Error::Verify {
        rule: "E_TRUST_NON_MEMBER_REJECTED".to_string(),
        message: format!(
            "Non-member acceptance rejected for {} '{}' ({})",
            approval_subject, reviewed.member_id, reviewed.kid
        ),
    }
}

pub(super) fn build_rewrap_rejection_error(path: &Path, approval_subject: &str) -> Error {
    Error::Verify {
        rule: "E_TRUST_APPROVAL_REJECTED".to_string(),
        message: format!(
            "Manual {} was rejected for rewrap input '{}'",
            approval_subject,
            format_path_relative_to_cwd(path)
        ),
    }
}
