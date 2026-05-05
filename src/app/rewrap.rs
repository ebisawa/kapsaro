// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for rewrap commands.

use crate::app::context::execution::build_write_execution_warnings;
use crate::app::context::execution::ExecutionContext;
use crate::app::trust::TrustApprovalCandidate;
use crate::Result;
use std::path::PathBuf;

pub(crate) mod artifact;
pub(crate) mod execution;
pub(crate) mod plan;
pub(crate) mod promotion;
pub(crate) mod rewrite;
pub(crate) mod session;
pub(crate) mod snapshot;
pub(crate) mod trust;
pub(crate) mod types;

use self::promotion::PromotionReviewView;
use self::types::RewrapBatchOutcome;
use crate::app::context::options::CommonCommandOptions;

pub(crate) struct RewrapBatchCommandInput {
    pub options: CommonCommandOptions,
    pub execution: ExecutionContext,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub explicit_targets: Vec<PathBuf>,
}

pub(crate) fn execute_rewrap_batch_command<
    EmitWarnings,
    ConfirmPromotions,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
>(
    input: RewrapBatchCommandInput,
    mut emit_warnings: EmitWarnings,
    mut confirm_promotions: ConfirmPromotions,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    confirm_recipients: ConfirmRecipients,
) -> Result<RewrapBatchOutcome>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmPromotions: FnMut(&PromotionReviewView) -> Result<Vec<String>>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str, &std::path::Path) -> Result<bool>,
    ConfirmNonMember:
        FnMut(&TrustApprovalCandidate, &str, &[String], &std::path::Path) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
{
    emit_warnings(&build_write_execution_warnings(&input.execution)?);
    let review_session =
        session::build_rewrap_review_session(&input, &mut confirm_promotions, confirm_recipients)?;
    emit_warnings(&review_session.review_warnings);
    let mut outcome = execution::execute_confirmed_rewrap_batch(
        review_session,
        input.execution,
        confirm_known,
        confirm_non_member,
    )?;
    emit_warnings(&outcome.warnings);
    outcome.warnings.clear();
    Ok(outcome)
}
