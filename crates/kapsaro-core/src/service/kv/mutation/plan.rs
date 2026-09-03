// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV mutation planning and write trust evaluation.
//! Builds the immutable review snapshot consumed by mutation execution.

use crate::feature::context::crypto::LocalKeyIdentity;
use crate::feature::envelope::wrap_set::WrapSet;
use crate::format::content::KvEncContent;
use crate::service::key::RecipientKeys;
use crate::service::kv::KvEncArtifact;
use crate::service::trust::{
    push_signature_verification_warnings, signer_outcome_from_decision, RecipientTrustOutcome,
    SignerTrustOutcome, TrustCommandSession, TrustContext, WriteRecipientTrustPlan,
    WriteTrustOptions,
};
use crate::service::workspace::{WorkspaceWriteCapabilities, WorkspaceWriteDirectories};
use crate::support::warning::push_unique_warning;
use crate::{Error, Result};

use super::super::session::KvCommandSession;
use super::snapshot::MutationReviewSnapshot;

pub struct MutationWriteTrustPlan<'a> {
    pub(super) options: WriteTrustOptions,
    pub(super) capabilities: WorkspaceWriteCapabilities<'a>,
    pub signer_trust: Option<SignerTrustOutcome>,
    pub recipient_trust: RecipientTrustOutcome,
    pub(crate) trust_context: TrustContext,
    pub warnings: Vec<String>,
    pub(super) review: MutationReviewSnapshot,
    command_warnings: Vec<String>,
    allow_missing: bool,
}

impl MutationWriteTrustPlan<'_> {
    pub fn ensure_current_after_confirmation(&self) -> Result<()> {
        self.review.ensure_current(&self.capabilities)
    }

    pub fn trust_session(&self) -> &TrustCommandSession {
        self.capabilities.trust()
    }

    #[cfg(test)]
    pub(crate) fn secrets_directory(
        &self,
    ) -> &std::sync::Arc<crate::support::fs::relative::OpenDir> {
        self.capabilities.secrets()
    }
}

struct ExistingSignerTrustEvaluation {
    signer_trust: Option<SignerTrustOutcome>,
    selected_key_expiry: Option<SelectedDecryptionKeyExpiry>,
    warnings: Vec<String>,
}

struct SelectedDecryptionKeyExpiry {
    warning: Option<String>,
    key_identity: LocalKeyIdentity,
}

struct MutationWriteReviewContext {
    recipient_review: WriteRecipientTrustPlan,
    review: MutationReviewSnapshot,
    signer_trust: Option<SignerTrustOutcome>,
    warnings: Vec<String>,
}

pub fn resolve_mutation_write_plan<'a>(
    directories: &'a WorkspaceWriteDirectories,
    trust_session: &'a TrustCommandSession,
    options: WriteTrustOptions,
    file_name: Option<&str>,
    allow_missing: bool,
) -> Result<MutationWriteTrustPlan<'a>> {
    let capabilities = WorkspaceWriteCapabilities::new(directories, trust_session);
    let command = KvCommandSession::bind_write(&capabilities, file_name)?;
    let context = resolve_mutation_write_review_context(
        options,
        &command,
        options.operation_options(),
        allow_missing,
    )?;
    let command_warnings = command.warnings.clone();
    drop(command);
    Ok(build_mutation_write_trust_plan(
        options,
        capabilities,
        command_warnings,
        context,
        allow_missing,
    ))
}

pub fn reevaluate_mutation_write_plan_after_review(
    plan: MutationWriteTrustPlan<'_>,
) -> Result<MutationWriteTrustPlan<'_>> {
    let MutationWriteTrustPlan {
        options,
        capabilities,
        review,
        command_warnings,
        allow_missing,
        ..
    } = plan;
    let command = KvCommandSession {
        target: review.target().clone(),
        capabilities: &capabilities,
        warnings: command_warnings.clone(),
    };
    let context = resolve_mutation_write_review_context(
        options,
        &command,
        options.operation_options(),
        allow_missing,
    )?;
    review.ensure_reviewed_state_matches(&context.review)?;
    ensure_reevaluated_trust_is_accepted(&context)?;
    drop(command);
    Ok(build_mutation_write_trust_plan(
        options,
        capabilities,
        command_warnings,
        context,
        allow_missing,
    ))
}

fn resolve_mutation_write_review_context(
    options: WriteTrustOptions,
    command: &KvCommandSession<'_>,
    operation_options: crate::service::operation::OperationOptions,
    allow_missing: bool,
) -> Result<MutationWriteReviewContext> {
    let recipient_review = resolve_mutation_recipient_review(options, command)?;
    let review = build_mutation_review_snapshot(command, &recipient_review, allow_missing)?;
    let existing_signer = evaluate_existing_signer_trust(
        review.existing_content(),
        &recipient_review,
        command.capabilities,
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

fn build_mutation_write_trust_plan<'a>(
    options: WriteTrustOptions,
    capabilities: WorkspaceWriteCapabilities<'a>,
    command_warnings: Vec<String>,
    context: MutationWriteReviewContext,
    allow_missing: bool,
) -> MutationWriteTrustPlan<'a> {
    MutationWriteTrustPlan {
        options,
        capabilities,
        signer_trust: context.signer_trust,
        recipient_trust: context.recipient_review.recipient_trust().clone(),
        trust_context: context.recipient_review.trust_context().clone(),
        warnings: context.warnings,
        review: context.review,
        command_warnings,
        allow_missing,
    }
}

fn ensure_reevaluated_trust_is_accepted(context: &MutationWriteReviewContext) -> Result<()> {
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

pub(super) fn build_mutation_review_changed_error() -> Error {
    Error::build_invalid_operation_error(
        "KV mutation trust changed and must be reviewed again.".to_string(),
    )
}

fn resolve_mutation_recipient_review(
    options: WriteTrustOptions,
    command: &KvCommandSession<'_>,
) -> Result<WriteRecipientTrustPlan> {
    WriteRecipientTrustPlan::load(
        command.capabilities,
        options,
        Some(
            command
                .capabilities
                .key_context()
                .inner()
                .local_key_identity(),
        ),
    )
}

fn build_mutation_review_snapshot(
    command: &KvCommandSession<'_>,
    recipient_review: &WriteRecipientTrustPlan,
    allow_missing: bool,
) -> Result<MutationReviewSnapshot> {
    MutationReviewSnapshot::build(
        command.target.clone(),
        recipient_review.workspace_members().clone(),
        command.capabilities,
        recipient_review.trust_context(),
        allow_missing,
    )
}

fn evaluate_existing_signer_trust(
    reviewed_file: Option<&KvEncContent>,
    recipient_review: &WriteRecipientTrustPlan,
    capabilities: &WorkspaceWriteCapabilities<'_>,
    allow_expired_key: bool,
) -> Result<ExistingSignerTrustEvaluation> {
    let selected_key_expiry =
        evaluate_existing_decryption_key_expiry(reviewed_file, capabilities, allow_expired_key)?;
    let mut warnings = Vec::new();
    let signer_trust = evaluate_signer_trust(
        reviewed_file,
        recipient_review,
        capabilities,
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
    capabilities: &WorkspaceWriteCapabilities<'_>,
    allow_expired_key: bool,
) -> Result<Option<SelectedDecryptionKeyExpiry>> {
    let Some(content) = reviewed_file else {
        return Ok(None);
    };
    let doc = content.parse()?;
    let wrap_set = WrapSet::parse(&doc.wrap().wrap, "Document")?;
    let selected = capabilities
        .key_context()
        .inner()
        .select_local_decryption_key(&wrap_set, capabilities.trust().owner().as_str())?;
    Ok(Some(SelectedDecryptionKeyExpiry {
        warning: selected
            .info()
            .key_expiry
            .enforce_expired_usage(allow_expired_key)?,
        key_identity: selected.info().key_identity.clone(),
    }))
}

fn evaluate_signer_trust(
    reviewed_file: Option<&KvEncContent>,
    recipient_review: &WriteRecipientTrustPlan,
    capabilities: &WorkspaceWriteCapabilities<'_>,
    local_key_identity: Option<&LocalKeyIdentity>,
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
    let evaluator = crate::service::trust::snapshot::load_trust_policy_evaluator(
        capabilities.trust(),
        members.active_members_by_kid().clone(),
    )?;
    let decision =
        evaluator.preflight_kv_mutation(&verified, &recipients, capabilities.key_context())?;
    let outcome = signer_outcome_from_decision(
        &decision,
        Some(verified.inner().proof().kid.as_str()),
        recipient_review.trust_context().review_available,
    )?;
    Ok(Some(outcome))
}
