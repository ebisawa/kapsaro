// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Persistence of reviewed trust approvals.
//! Saves caller-approved known keys under the trust store lock.

use crate::app::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::Result;

use super::execution::TrustExecutionContext;

pub fn save_approved_known_key_documents(
    execution: TrustExecutionContext<'_>,
    approvals: &[ApprovedKnownKey],
) -> Result<()> {
    save_known_key_approvals(execution.options, execution.execution, approvals).map(|_| ())
}
