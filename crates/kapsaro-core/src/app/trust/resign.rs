// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Explicit re-signing of the local trust store after a signing key rotation.
//! Moves the stored signature to the current signing key without touching approvals.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::store::{
    execute_trust_store_resign_with_execution, TrustStoreResignOutcome,
};
use crate::feature::trust::store_mutation::TrustStoreWrite;
use crate::Result;

#[derive(Debug, Clone)]
pub struct TrustStoreResignResult {
    pub owner_handle: String,
    pub previous_signer_kid: String,
    pub signer_kid: String,
    /// Whether the signature actually moved to another key.
    pub resigned: bool,
}

/// Re-sign the stored trust store with the member's current signing key.
///
/// The approvals are only re-signed once they verify under the key that signed
/// them, so a store whose signer key is gone is reported rather than resealed
/// with content nothing has vouched for.
pub fn resign_trust_store_command(
    options: &CommonCommandOptions,
    execution: &ExecutionContext,
) -> Result<TrustStoreResignResult> {
    let outcome = execute_trust_store_resign_with_execution(options, execution)?;
    Ok(build_resign_result(
        execution.member_handle.as_str(),
        outcome,
    ))
}

fn build_resign_result(
    owner_handle: &str,
    outcome: TrustStoreResignOutcome,
) -> TrustStoreResignResult {
    TrustStoreResignResult {
        owner_handle: owner_handle.to_string(),
        previous_signer_kid: outcome.previous_signer_kid.into_string(),
        signer_kid: outcome.signer_kid,
        resigned: matches!(outcome.write, TrustStoreWrite::Resign),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_trust_resign_test.rs"]
mod tests;
