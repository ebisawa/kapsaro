// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV mutation execution after review.
//! Rechecks snapshots, performs the feature write, and persists trust before replacement.

use crate::api::key::{LocalKeyStore, RecipientKeys};
use crate::api::kv::{AuthorizedKvMutation, KvEncArtifact, KvMutationOperation};
use crate::api::trust::{
    CurrentMemberSnapshot, LocalTrustStore, TrustDecision, TrustPolicyEvaluator, TrustReviewKind,
    TrustReviewRequest,
};
use crate::app::errors::build_kv_key_not_found_error;
use crate::app::trust::review::{
    review_artifact_recipient_set_output, ArtifactRecipientSetReviewInput, TrustExecutionContext,
};
use crate::app::trust::{
    evaluate_output_recipient_set_trust, ArtifactRecipientTrustOutcome, WriteTrustPolicy,
};
use crate::feature::artifact::artifact_recipient_evidence;
use crate::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot,
    KvWriteContext,
};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::format::content::KvEncContent;
use crate::format::kv::dotenv::{parse_dotenv, validate_dotenv_strict};
use crate::support::fs::lock;
use crate::support::fs::relative::DirectoryFd;
use crate::{Error, Result};

use super::super::types::{KvImportResult, KvInputEntry, KvWriteOutcome};
use super::plan::{build_mutation_review_changed_error, MutationWriteTrustPlan};
use super::snapshot::MutationTrustStoreSnapshot;

#[cfg(test)]
thread_local! {
    static AUTHORIZED_MUTATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static POST_RECIPIENT_APPROVAL_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static POST_AUTHORIZED_MUTATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

struct MutationAuthorizationContext {
    evaluator: TrustPolicyEvaluator,
    trust_store: MutationTrustStoreSnapshot,
}

struct ExistingMutationReview<'a, P, D> {
    plan: &'a MutationWriteTrustPlan<P>,
    existing: &'a KvEncContent,
    locked_secrets_dir: &'a D,
    warnings: &'a mut Vec<String>,
    output: ArtifactRecipientSet,
    app_outcome: ArtifactRecipientTrustOutcome,
    recipients: &'a RecipientKeys,
}

pub fn set_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    entries: Vec<KvInputEntry>,
    success_message: Option<&str>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<KvWriteOutcome>
where
    P: WriteTrustPolicy,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let entries = to_feature_entries(entries);
    execute_kv_mutation(
        plan,
        success_message,
        |existing_content, recipients, ctx| {
            let result = set_kv_entry_with_recipients(existing_content, &entries, recipients, ctx)?;
            Ok(result.encrypted.as_str().to_owned())
        },
        KvMutationOperation::Set,
        |authorized| {
            authorized
                .set_internal_entries(&entries)
                .map(|artifact| artifact.as_str().to_owned())
        },
        confirm_recipient_set,
    )
}

pub fn unset_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    key: &str,
    success_message: Option<&str>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<KvWriteOutcome>
where
    P: WriteTrustPolicy,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    execute_kv_mutation(
        plan,
        success_message,
        |existing_content, recipients, ctx| {
            let kv_content = existing_content
                .ok_or_else(|| Error::build_config_error("File content is required".to_string()))?;
            unset_kv_entry_with_recipients(kv_content, key, recipients, ctx)
                .map_err(|e| build_kv_key_not_found_error(e, &plan.review.target().file_path, key))
        },
        KvMutationOperation::Unset,
        |authorized| {
            authorized
                .unset_entry(key)
                .map(|artifact| artifact.as_str().to_owned())
        },
        confirm_recipient_set,
    )
}

pub fn import_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    dotenv_content: &str,
    success_message: Option<&str>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<(KvWriteOutcome, usize)>
where
    P: WriteTrustPolicy,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let result =
        import_kv_command_result(plan, dotenv_content, success_message, confirm_recipient_set)?;
    Ok((result.write_outcome, result.entry_count))
}

fn import_kv_command_result<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    dotenv_content: &str,
    success_message: Option<&str>,
    confirm_recipient_set: ConfirmRecipientSet,
) -> Result<KvImportResult>
where
    P: WriteTrustPolicy,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    validate_dotenv_strict(dotenv_content)?;
    let kv_map = parse_dotenv(dotenv_content)?;
    let entries: Vec<KvInputEntry> = kv_map
        .into_iter()
        .map(|(key, value)| KvInputEntry::new_secret(key, value))
        .collect();
    let entry_count = entries.len();
    let write_outcome = set_kv_command_with_recipient_set_confirmation(
        plan,
        entries,
        success_message,
        confirm_recipient_set,
    )?;
    Ok(KvImportResult {
        write_outcome,
        entry_count,
    })
}

fn execute_kv_mutation<P, F, AuthorizedOperation>(
    plan: &MutationWriteTrustPlan<P>,
    success_message: Option<&str>,
    create_operation: F,
    operation: KvMutationOperation,
    authorized_operation: AuthorizedOperation,
    mut confirm_recipient_set: impl FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
) -> Result<KvWriteOutcome>
where
    P: WriteTrustPolicy,
    F: FnOnce(Option<&KvEncContent>, &KvRecipientSnapshot, &KvWriteContext<'_>) -> Result<String>,
    AuthorizedOperation: FnOnce(&AuthorizedKvMutation<'_>) -> Result<String>,
{
    let secrets_dir = plan.review.target().workspace_root.secrets_dir();
    lock::with_locked_dir(&secrets_dir, |locked_secrets_dir| {
        plan.review.ensure_current_at(locked_secrets_dir)?;
        plan.execution
            .key_ctx
            .inner()
            .enforce_signing_key_not_expired()?;
        let mut warnings = Vec::new();
        let encrypted = match plan.review.existing_content() {
            Some(existing) => execute_existing_kv_mutation(
                plan,
                existing,
                operation,
                authorized_operation,
                locked_secrets_dir,
                &mut warnings,
                &mut confirm_recipient_set,
            )?,
            None => execute_new_kv_mutation(
                plan,
                create_operation,
                locked_secrets_dir,
                &mut warnings,
                &mut confirm_recipient_set,
            )?,
        };
        plan.review
            .save_replacement_at(locked_secrets_dir, &encrypted)?;
        Ok(KvWriteOutcome {
            message: success_message.map(ToOwned::to_owned),
            warnings,
        })
    })
}

fn execute_new_kv_mutation<P, F, D, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    create_operation: F,
    locked_secrets_dir: &D,
    warnings: &mut Vec<String>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<String>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
    F: FnOnce(Option<&KvEncContent>, &KvRecipientSnapshot, &KvWriteContext<'_>) -> Result<String>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let write_ctx = KvWriteContext::new(
        &plan.execution.member_handle,
        plan.execution.key_ctx.inner(),
    );
    let encrypted = create_operation(None, plan.review.recipients(), &write_ctx)?;
    let content = plan.review.encrypted_content(encrypted.clone());
    let sid = review_new_kv_recipient_set(
        plan,
        &content,
        locked_secrets_dir,
        warnings,
        confirm_recipient_set,
    )?;
    run_post_recipient_approval_hook();
    plan.review.ensure_target_current_at(locked_secrets_dir)?;
    let recipients = build_authorized_recipient_keys(plan)?;
    let current = load_mutation_authorization(plan, &recipients)?;
    let decision =
        current
            .evaluator
            .evaluate_new_kv_output(sid, &recipients, &plan.execution.key_ctx)?;
    if matches!(decision, TrustDecision::ReviewRequired(_)) {
        return Err(build_mutation_review_changed_error());
    }
    enforce_final_snapshot(plan, locked_secrets_dir, &current.trust_store)?;
    Ok(encrypted)
}

fn execute_existing_kv_mutation<P, AuthorizedOperation, D, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    existing: &KvEncContent,
    operation: KvMutationOperation,
    authorized_operation: AuthorizedOperation,
    locked_secrets_dir: &D,
    warnings: &mut Vec<String>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<String>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
    AuthorizedOperation: FnOnce(&AuthorizedKvMutation<'_>) -> Result<String>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let artifact = KvEncArtifact::parse(existing.as_str())?;
    let verified = artifact.verify(plan.options.operation_options())?;
    let recipients = build_authorized_recipient_keys(plan)?;
    let initial = load_mutation_authorization(plan, &recipients)?;
    let decision = initial.evaluator.evaluate_kv_mutation(
        &verified,
        &recipients,
        &plan.execution.key_ctx,
        operation,
        plan.options.operation_options(),
    )?;
    let output = build_output_recipient_set(&verified, &recipients)?;
    let app_outcome =
        evaluate_output_recipient_set_trust(&plan.trust_context, &output, P::CAPABILITY)?;
    match decision {
        TrustDecision::Trusted(authorized) => {
            enforce_app_accepts_recipient_set(&app_outcome)?;
            let encrypted = execute_authorized_operation(&authorized, authorized_operation)?;
            enforce_final_snapshot(plan, locked_secrets_dir, &initial.trust_store)?;
            Ok(encrypted)
        }
        TrustDecision::ReviewRequired(requests) => review_and_execute_existing_mutation(
            ExistingMutationReview {
                plan,
                existing,
                locked_secrets_dir,
                warnings,
                output,
                app_outcome,
                recipients: &recipients,
            },
            operation,
            authorized_operation,
            confirm_recipient_set,
            requests,
        ),
    }
}

fn build_authorized_recipient_keys<P>(plan: &MutationWriteTrustPlan<P>) -> Result<RecipientKeys>
where
    P: WriteTrustPolicy,
{
    let recipients = plan.review.recipients();
    RecipientKeys::from_verified_parts(
        recipients.member_handles.clone(),
        recipients.verified_members.clone(),
    )
}

fn load_mutation_authorization<P>(
    plan: &MutationWriteTrustPlan<P>,
    recipients: &RecipientKeys,
) -> Result<MutationAuthorizationContext>
where
    P: WriteTrustPolicy,
{
    let members = CurrentMemberSnapshot::from_recipient_keys(recipients)?;
    let base_dir = plan.options.resolve_base_dir()?;
    let key_store = LocalKeyStore::new(plan.options.resolve_keystore_root()?);
    let trust_store = LocalTrustStore::new(base_dir, plan.execution.member_handle.to_string());
    let loaded = trust_store.load_verified(&key_store)?;
    let protected = loaded.as_ref().map(|store| store.protected().clone());
    let store = loaded.map(|store| store.into_store());
    Ok(MutationAuthorizationContext {
        evaluator: TrustPolicyEvaluator::new(members, store),
        trust_store: MutationTrustStoreSnapshot::from_protected(
            &plan.options,
            &plan.execution.member_handle,
            protected,
        ),
    })
}

fn review_new_kv_recipient_set<P, D, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    content: &crate::format::content::EncContent,
    locked_secrets_dir: &D,
    warnings: &mut Vec<String>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<uuid::Uuid>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let evidence = artifact_recipient_evidence(content)?;
    let sid = evidence.recipient_set.sid();
    review_artifact_recipient_set_output(
        TrustExecutionContext {
            options: &plan.options,
            execution: &plan.execution,
            warnings: &[],
        },
        ArtifactRecipientSetReviewInput {
            trust_ctx: &plan.trust_context,
            recipient_set: &evidence.recipient_set,
            capability: P::CAPABILITY,
            context_label: "kv output member set",
        },
        &mut |new_warnings| warnings.extend_from_slice(new_warnings),
        |outcome, context_label| {
            let confirmed = confirm_recipient_set(outcome, context_label)?;
            plan.review.ensure_current_at(locked_secrets_dir)?;
            Ok(confirmed)
        },
    )?;
    Ok(sid)
}

fn review_and_execute_existing_mutation<P, AuthorizedOperation, D, ConfirmRecipientSet>(
    review: ExistingMutationReview<'_, P, D>,
    operation: KvMutationOperation,
    authorized_operation: AuthorizedOperation,
    confirm_recipient_set: &mut ConfirmRecipientSet,
    requests: Vec<TrustReviewRequest>,
) -> Result<String>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
    AuthorizedOperation: FnOnce(&AuthorizedKvMutation<'_>) -> Result<String>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    enforce_app_reviews_recipient_set(&requests, &review.app_outcome, &review.output)?;
    review_existing_recipient_set(
        review.plan,
        &review.output,
        &review.app_outcome,
        review.locked_secrets_dir,
        review.warnings,
        confirm_recipient_set,
    )?;
    run_post_recipient_approval_hook();
    review
        .plan
        .review
        .ensure_target_current_at(review.locked_secrets_dir)?;
    let artifact = KvEncArtifact::parse(review.existing.as_str())?;
    let verified = artifact.verify(review.plan.options.operation_options())?;
    let current = load_mutation_authorization(review.plan, review.recipients)?;
    let decision = current.evaluator.evaluate_kv_mutation(
        &verified,
        review.recipients,
        &review.plan.execution.key_ctx,
        operation,
        review.plan.options.operation_options(),
    )?;
    let TrustDecision::Trusted(authorized) = decision else {
        return Err(build_mutation_review_changed_error());
    };
    let encrypted = execute_authorized_operation(&authorized, authorized_operation)?;
    enforce_final_snapshot(review.plan, review.locked_secrets_dir, &current.trust_store)?;
    Ok(encrypted)
}

fn review_existing_recipient_set<P, D, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    output: &ArtifactRecipientSet,
    outcome: &ArtifactRecipientTrustOutcome,
    locked_secrets_dir: &D,
    warnings: &mut Vec<String>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<()>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    review_artifact_recipient_set_output(
        TrustExecutionContext {
            options: &plan.options,
            execution: &plan.execution,
            warnings: &[],
        },
        ArtifactRecipientSetReviewInput {
            trust_ctx: &plan.trust_context,
            recipient_set: output,
            capability: P::CAPABILITY,
            context_label: "kv output member set",
        },
        &mut |new_warnings| warnings.extend_from_slice(new_warnings),
        |review_outcome, context_label| {
            if review_outcome != outcome {
                return Err(build_mutation_review_changed_error());
            }
            let confirmed = confirm_recipient_set(review_outcome, context_label)?;
            plan.review.ensure_current_at(locked_secrets_dir)?;
            Ok(confirmed)
        },
    )
}

fn build_output_recipient_set(
    artifact: &crate::api::kv::VerifiedKvEncArtifact,
    recipients: &RecipientKeys,
) -> Result<ArtifactRecipientSet> {
    let sid = artifact.recipient_set_subject()?.sid();
    let public_keys = recipients
        .keys()
        .iter()
        .map(|key| key.document().clone())
        .collect::<Vec<_>>();
    ArtifactRecipientSet::from_public_keys(sid, &public_keys)
}

fn enforce_app_accepts_recipient_set(outcome: &ArtifactRecipientTrustOutcome) -> Result<()> {
    if matches!(outcome, ArtifactRecipientTrustOutcome::Accepted) {
        return Ok(());
    }
    Err(build_mutation_review_changed_error())
}

fn enforce_app_reviews_recipient_set(
    requests: &[TrustReviewRequest],
    outcome: &ArtifactRecipientTrustOutcome,
    output: &ArtifactRecipientSet,
) -> Result<()> {
    let ArtifactRecipientTrustOutcome::NeedsManualApproval(review) = outcome else {
        return Err(build_mutation_review_changed_error());
    };
    let expected_kind = if review.has_approved_set() {
        TrustReviewKind::ChangedRecipientSet
    } else {
        TrustReviewKind::RecipientSet
    };
    let [request] = requests else {
        return Err(build_mutation_review_changed_error());
    };
    if request.kind() == expected_kind
        && request.sid() == Some(output.sid_string().as_str())
        && request.recipient_kids() == output.recipient_kids()
    {
        return Ok(());
    }
    Err(build_mutation_review_changed_error())
}

fn enforce_final_snapshot<P, D>(
    plan: &MutationWriteTrustPlan<P>,
    locked_secrets_dir: &D,
    trust_store: &MutationTrustStoreSnapshot,
) -> Result<()>
where
    D: DirectoryFd,
{
    plan.review.ensure_target_current_at(locked_secrets_dir)?;
    trust_store.ensure_current()
}

fn execute_authorized_operation<AuthorizedOperation>(
    authorized: &AuthorizedKvMutation<'_>,
    operation: AuthorizedOperation,
) -> Result<String>
where
    AuthorizedOperation: FnOnce(&AuthorizedKvMutation<'_>) -> Result<String>,
{
    #[cfg(test)]
    AUTHORIZED_MUTATION_COUNT.with(|count| count.set(count.get() + 1));
    let encrypted = operation(authorized)?;
    run_post_authorized_mutation_hook();
    Ok(encrypted)
}

#[cfg(test)]
pub(crate) fn reset_authorized_mutation_count() {
    AUTHORIZED_MUTATION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn authorized_mutation_count() -> usize {
    AUTHORIZED_MUTATION_COUNT.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn set_post_recipient_approval_hook(hook: impl FnOnce() + 'static) {
    POST_RECIPIENT_APPROVAL_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
}

#[cfg(test)]
pub(crate) fn set_post_authorized_mutation_hook(hook: impl FnOnce() + 'static) {
    POST_AUTHORIZED_MUTATION_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
}

#[cfg(test)]
fn run_post_recipient_approval_hook() {
    let hook = POST_RECIPIENT_APPROVAL_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_post_recipient_approval_hook() {}

#[cfg(test)]
fn run_post_authorized_mutation_hook() {
    let hook = POST_AUTHORIZED_MUTATION_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_post_authorized_mutation_hook() {}

fn to_feature_entries(entries: Vec<KvInputEntry>) -> Vec<crate::feature::kv::types::KvInputEntry> {
    entries
        .into_iter()
        .map(KvInputEntry::into_feature)
        .collect()
}
