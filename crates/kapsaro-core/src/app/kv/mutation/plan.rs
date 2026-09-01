// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV mutation planning and write trust evaluation.
//! Builds the immutable review snapshot consumed by mutation execution.

use std::marker::PhantomData;

use crate::app::context::execution::{
    evaluate_selected_decryption_key_expiry, ExecutionContext, SelectedDecryptionKeyExpiry,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::{
    push_signature_verification_warnings, signer_outcome_from_decision, RecipientTrustOutcome,
    SignerTrustOutcome, TrustContext, WriteRecipientTrustPlan, WriteTrustPolicy,
};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::format::content::KvEncContent;
use crate::service::key::RecipientKeys;
use crate::service::kv::KvEncArtifact;
use crate::support::warning::push_unique_warning;
use crate::{Error, Result};

use super::super::session::KvCommandSession;
use super::snapshot::MutationReviewSnapshot;

pub struct MutationWriteTrustPlan<'a, P> {
    pub(super) options: CommonCommandOptions,
    pub execution: &'a ExecutionContext,
    pub signer_trust: Option<SignerTrustOutcome>,
    pub recipient_trust: RecipientTrustOutcome,
    pub(crate) trust_context: TrustContext,
    pub warnings: Vec<String>,
    pub(super) review: MutationReviewSnapshot<'a>,
    command_warnings: Vec<String>,
    allow_missing: bool,
    _policy: PhantomData<P>,
}

impl<P> MutationWriteTrustPlan<'_, P> {
    /// Ensure the reviewed artifact, members, and trust store still match.
    pub fn ensure_current_after_confirmation(&self) -> Result<()> {
        self.review.ensure_current()
    }
}

struct ExistingSignerTrustEvaluation {
    signer_trust: Option<SignerTrustOutcome>,
    selected_key_expiry: Option<SelectedDecryptionKeyExpiry>,
    warnings: Vec<String>,
}

struct MutationWriteReviewContext<'a, P>
where
    P: WriteTrustPolicy,
{
    recipient_review: WriteRecipientTrustPlan<P>,
    review: MutationReviewSnapshot<'a>,
    signer_trust: Option<SignerTrustOutcome>,
    warnings: Vec<String>,
}

pub fn resolve_mutation_write_plan<'a, P>(
    options: &CommonCommandOptions,
    execution: &'a ExecutionContext,
    file_name: Option<&str>,
    allow_missing: bool,
) -> Result<MutationWriteTrustPlan<'a, P>>
where
    P: WriteTrustPolicy,
{
    let command = KvCommandSession::bind_write(execution, file_name)?;
    let operation_options = options.operation_options();
    let context = resolve_mutation_write_review_context::<P>(
        options,
        &command,
        operation_options,
        allow_missing,
    )?;
    Ok(build_mutation_write_trust_plan(
        options,
        command,
        context,
        allow_missing,
    ))
}

pub fn reevaluate_mutation_write_plan_after_review<P>(
    plan: MutationWriteTrustPlan<'_, P>,
) -> Result<MutationWriteTrustPlan<'_, P>>
where
    P: WriteTrustPolicy,
{
    let command = KvCommandSession {
        target: plan.review.target().clone(),
        execution: plan.execution,
        warnings: plan.command_warnings,
    };
    let context = resolve_mutation_write_review_context::<P>(
        &plan.options,
        &command,
        plan.options.operation_options(),
        plan.allow_missing,
    )?;
    plan.review.ensure_reviewed_state_matches(&context.review)?;
    ensure_reevaluated_trust_is_accepted(&context)?;
    Ok(build_mutation_write_trust_plan(
        &plan.options,
        command,
        context,
        plan.allow_missing,
    ))
}

fn resolve_mutation_write_review_context<'a, P>(
    options: &CommonCommandOptions,
    command: &KvCommandSession<'a>,
    operation_options: crate::service::operation::OperationOptions,
    allow_missing: bool,
) -> Result<MutationWriteReviewContext<'a, P>>
where
    P: WriteTrustPolicy,
{
    let recipient_review = resolve_mutation_recipient_review::<P>(options, command)?;
    let review = build_mutation_review_snapshot(command, &recipient_review, allow_missing)?;
    let existing_signer = evaluate_existing_signer_trust(
        review.existing_content(),
        &recipient_review,
        command.execution,
        operation_options.allow_expired_key(),
    )?;
    let warnings = collect_mutation_write_warnings(
        command.warnings.clone(),
        existing_signer.selected_key_expiry,
        existing_signer.warnings.clone(),
        recipient_review.warnings(),
    );
    Ok(MutationWriteReviewContext {
        recipient_review,
        review,
        signer_trust: existing_signer.signer_trust,
        warnings,
    })
}

fn build_mutation_write_trust_plan<'a, P>(
    options: &CommonCommandOptions,
    command: KvCommandSession<'a>,
    context: MutationWriteReviewContext<'a, P>,
    allow_missing: bool,
) -> MutationWriteTrustPlan<'a, P>
where
    P: WriteTrustPolicy,
{
    MutationWriteTrustPlan {
        options: options.clone(),
        execution: command.execution,
        signer_trust: context.signer_trust,
        recipient_trust: context.recipient_review.recipient_trust().clone(),
        trust_context: context.recipient_review.trust_context().clone(),
        warnings: context.warnings,
        review: context.review,
        command_warnings: command.warnings,
        allow_missing,
        _policy: PhantomData,
    }
}

fn ensure_reevaluated_trust_is_accepted<P>(
    context: &MutationWriteReviewContext<'_, P>,
) -> Result<()>
where
    P: WriteTrustPolicy,
{
    let signer_accepted = context
        .signer_trust
        .as_ref()
        .is_none_or(|outcome| matches!(outcome, SignerTrustOutcome::Accepted));
    let recipients_accepted = matches!(
        context.recipient_review.recipient_trust(),
        RecipientTrustOutcome::Accepted
    );
    if signer_accepted && recipients_accepted {
        return Ok(());
    }
    Err(build_mutation_review_changed_error())
}

/// Build the error raised when trust state no longer matches what the user reviewed.
pub(super) fn build_mutation_review_changed_error() -> Error {
    Error::build_invalid_operation_error(
        "KV mutation trust changed and must be reviewed again.".to_string(),
    )
}

fn resolve_mutation_recipient_review<P>(
    options: &CommonCommandOptions,
    command: &KvCommandSession,
) -> Result<WriteRecipientTrustPlan<P>>
where
    P: WriteTrustPolicy,
{
    let keystore = command
        .execution
        .require_local_keystore_access("KV mutation")?;
    WriteRecipientTrustPlan::<P>::load(
        options,
        command.execution,
        Some(command.execution.key_ctx.inner().local_key_identity()),
        keystore,
    )
}

fn build_mutation_review_snapshot<'a, P>(
    command: &KvCommandSession<'a>,
    recipient_review: &WriteRecipientTrustPlan<P>,
    allow_missing: bool,
) -> Result<MutationReviewSnapshot<'a>>
where
    P: WriteTrustPolicy,
{
    MutationReviewSnapshot::build(
        command.target.clone(),
        recipient_review.workspace_members().clone(),
        command.execution,
        recipient_review.trust_context(),
        allow_missing,
    )
}

fn evaluate_existing_signer_trust(
    reviewed_file: Option<&KvEncContent>,
    recipient_review: &WriteRecipientTrustPlan<impl WriteTrustPolicy>,
    execution: &ExecutionContext,
    allow_expired_key: bool,
) -> Result<ExistingSignerTrustEvaluation> {
    let selected_key_expiry =
        evaluate_existing_decryption_key_expiry(reviewed_file, execution, allow_expired_key)?;
    let mut warnings = Vec::new();
    let signer_trust = evaluate_signer_trust(
        reviewed_file,
        recipient_review,
        execution,
        selected_key_expiry
            .as_ref()
            .map(|expiry| &expiry.key_identity),
        allow_expired_key,
        &mut warnings,
    )?;
    Ok(ExistingSignerTrustEvaluation {
        signer_trust,
        selected_key_expiry,
        warnings,
    })
}

fn collect_mutation_write_warnings(
    mut warnings: Vec<String>,
    selected_key_expiry: Option<SelectedDecryptionKeyExpiry>,
    signer_warnings: Vec<String>,
    recipient_warnings: &[String],
) -> Vec<String> {
    warnings.extend(signer_warnings);
    if let Some(warning) = selected_key_expiry.and_then(|expiry| expiry.warning) {
        push_unique_warning(&mut warnings, warning);
    }
    warnings.extend(recipient_warnings.iter().cloned());
    warnings
}

fn evaluate_existing_decryption_key_expiry(
    reviewed_file: Option<&KvEncContent>,
    execution: &ExecutionContext,
    allow_expired_key: bool,
) -> Result<Option<SelectedDecryptionKeyExpiry>> {
    let Some(content) = reviewed_file else {
        return Ok(None);
    };
    let doc = content.parse()?;
    let wrap_set = WrapSet::parse(&doc.wrap().wrap, "Document")?;
    evaluate_selected_decryption_key_expiry(execution, &wrap_set, allow_expired_key).map(Some)
}

fn evaluate_signer_trust(
    reviewed_file: Option<&KvEncContent>,
    recipient_review: &WriteRecipientTrustPlan<impl WriteTrustPolicy>,
    execution: &ExecutionContext,
    local_key_identity: Option<&crate::feature::context::crypto::LocalKeyIdentity>,
    allow_expired_key: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<SignerTrustOutcome>> {
    let Some(content) = reviewed_file else {
        return Ok(None);
    };

    let verified = KvEncArtifact::parse(content.as_str())?.verify(
        crate::service::operation::OperationOptions::new()
            .with_allow_expired_key(allow_expired_key),
    )?;
    push_signature_verification_warnings(warnings, verified.inner().proof(), local_key_identity)?;
    let members = recipient_review.workspace_members();
    let recipients = RecipientKeys::from_verified_parts(
        members.member_handles().to_vec(),
        members.verified_recipients().to_vec(),
    )?;
    let evaluator = crate::app::trust::snapshot::load_trust_policy_evaluator(
        execution,
        members.active_members_by_kid().clone(),
    )?;
    let decision = evaluator.preflight_kv_mutation(&verified, &recipients, &execution.key_ctx)?;
    let signer_kid = verified.inner().proof().kid.as_str();
    let outcome = signer_outcome_from_decision(
        &decision,
        Some(signer_kid),
        recipient_review.trust_context().is_interactive,
    )?;
    Ok(Some(outcome))
}
