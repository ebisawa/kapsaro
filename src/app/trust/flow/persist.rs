// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::approval::{commit_known_key_approvals, ApprovedKnownKey};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::collections::BTreeSet;
use std::path::Path;

use super::execute::TrustExecutionContext;

pub(super) fn persist_approved_known_keys<EmitWarnings>(
    execution: TrustExecutionContext<'_>,
    approvals: &[ApprovedKnownKey],
    emit_warnings: &mut EmitWarnings,
) -> Result<()>
where
    EmitWarnings: FnMut(&[String]),
{
    if approvals.is_empty() {
        return Ok(());
    }

    let result = commit_known_key_approvals(execution.options, execution.execution, approvals)?;
    emit_warnings(&result.warnings);
    Ok(())
}

pub(super) fn build_rewrap_rejection_error(path: &Path, approval_subject: &str) -> Error {
    Error::Verify {
        rule: "E_TRUST_APPROVAL_REJECTED".to_string(),
        message: format!(
            "Manual {} was rejected for rewrap input '{}'",
            approval_subject,
            display_path_relative_to_cwd(path)
        ),
    }
}

pub(super) fn dedupe_approved_known_keys(
    approvals: Vec<ApprovedKnownKey>,
) -> Vec<ApprovedKnownKey> {
    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();

    for approval in approvals {
        if seen.insert(KnownKeyIdentity::from(&approval)) {
            deduped.push(approval);
        }
    }

    deduped
}
