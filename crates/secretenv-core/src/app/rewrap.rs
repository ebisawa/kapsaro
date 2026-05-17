// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for rewrap commands.

use crate::app::context::execution::build_write_execution_warnings;
use crate::app::context::execution::ExecutionContext;
use crate::app::trust::TrustApprovalCandidate;
use crate::Result;
use std::path::PathBuf;

pub mod artifact;
pub mod execution;
pub mod plan;
pub mod promotion;
pub mod rewrite;
pub mod session;
pub mod snapshot;
pub mod trust;
pub mod types;

use self::promotion::PromotionReviewView;
use self::types::RewrapBatchOutcome;
use crate::app::context::options::CommonCommandOptions;

pub struct RewrapBatchCommandInput {
    pub options: CommonCommandOptions,
    pub execution: ExecutionContext,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub explicit_targets: Vec<PathBuf>,
}

pub fn execute_rewrap_batch_command<
    EmitWarnings,
    ConfirmPromotions,
    ConfirmKnown,
    ConfirmNonMember,
    ConfirmRecipients,
    ConfirmRecipientSet,
>(
    input: RewrapBatchCommandInput,
    mut emit_warnings: EmitWarnings,
    mut confirm_promotions: ConfirmPromotions,
    confirm_known: ConfirmKnown,
    confirm_non_member: ConfirmNonMember,
    mut confirm_recipients: ConfirmRecipients,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<RewrapBatchOutcome>
where
    EmitWarnings: FnMut(&[String]),
    ConfirmPromotions: FnMut(&PromotionReviewView) -> Result<Vec<String>>,
    ConfirmKnown: FnMut(&TrustApprovalCandidate, &str) -> Result<bool>,
    ConfirmNonMember: FnMut(&TrustApprovalCandidate, &str, &[String]) -> Result<bool>,
    ConfirmRecipients:
        FnMut(&[TrustApprovalCandidate], &str) -> Result<Vec<TrustApprovalCandidate>>,
    ConfirmRecipientSet:
        FnMut(&crate::app::trust::ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    emit_warnings(&build_write_execution_warnings(&input.execution)?);
    let review_session = session::build_rewrap_review_session(
        &input,
        &mut confirm_promotions,
        &mut confirm_recipients,
    )?;
    emit_warnings(&review_session.review_warnings);
    let mut outcome = execution::execute_confirmed_rewrap_batch(
        review_session,
        input.execution,
        confirm_known,
        confirm_non_member,
        &mut confirm_recipients,
        confirm_recipient_set,
    )?;
    emit_warnings(&outcome.warnings);
    outcome.warnings.clear();
    Ok(outcome)
}
