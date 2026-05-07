// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::approval::{
    save_known_key_approvals, save_recipient_set_approval, ApprovedKnownKey,
};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::Result;

use super::execution::TrustExecutionContext;

pub(super) fn save_approved_known_keys<EmitWarnings>(
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

    let result = save_known_key_approvals(execution.options, execution.execution, approvals)?;
    emit_warnings(&result.warnings);
    Ok(())
}

pub(crate) fn save_approved_known_key_warnings(
    execution: TrustExecutionContext<'_>,
    approvals: &[ApprovedKnownKey],
) -> Result<Vec<String>> {
    if approvals.is_empty() {
        return Ok(Vec::new());
    }

    Ok(save_known_key_approvals(execution.options, execution.execution, approvals)?.warnings)
}

pub(super) fn save_approved_recipient_set<EmitWarnings>(
    execution: TrustExecutionContext<'_>,
    approval: Option<ArtifactRecipientSet>,
    emit_warnings: &mut EmitWarnings,
) -> Result<()>
where
    EmitWarnings: FnMut(&[String]),
{
    if approval.is_none() {
        return Ok(());
    }

    let result = save_recipient_set_approval(execution.options, execution.execution, approval)?;
    emit_warnings(&result.warnings);
    Ok(())
}
