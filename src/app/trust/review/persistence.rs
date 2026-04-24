// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
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
