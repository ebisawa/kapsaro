// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV mutation execution after review.
//! Rechecks snapshots, performs the feature write, and persists trust before replacement.
//!
//! The review runs before the secrets directory is locked, and the write that
//! commits it runs inside the lock. A recipient-set review can stop at a prompt
//! for as long as the operator takes to answer, and a directory lock is given
//! up on a timeout, so holding one across the prompt would fail every other
//! kapsaro process working the same tree. Nothing the approval rests on is
//! carried over on trust: the target and the member set are compared against
//! the review again once the lock is held, and the authorization is derived
//! afresh from the trust store on disk rather than from the decision the review
//! reached. A concurrent write is reported and the mutation abandoned.

use crate::api::key::RecipientKeys;
use crate::api::kv::{AuthorizedKvMutation, KvEncArtifact, KvMutationOperation};
use crate::api::trust::{
    CurrentMemberSnapshot, TrustDecision, TrustPolicyEvaluator, TrustReviewKind, TrustReviewRequest,
};
use crate::app::context::review::ReviewedTrustStore;
use crate::app::errors::build_kv_key_not_found_error;
use crate::app::trust::review::{
    review_artifact_recipient_set_output, ArtifactRecipientSetReviewInput, TrustExecutionContext,
};
use crate::app::trust::store::load_verified_local_trust_store;
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
use crate::support::fs::lock::with_exclusive_locked_directory;
use crate::support::fs::relative::DirectoryFd;
use crate::{Error, Result};
use std::sync::Arc;

use super::super::types::{KvImportResult, KvInputEntry, KvWriteOutcome};
use super::plan::{build_mutation_review_changed_error, MutationWriteTrustPlan};
use super::snapshot::KV_TRUST_STORE_CHANGED_MESSAGE;

// Test-only seams. The counter records how many times an authorized mutation
// actually ran, and the two hooks fire where a test can change the trust store
// or the document between the review and the write that commits it. Only a call
// point inside the production flow can reach those moments, so the seams live
// here and compile out of production builds.
#[cfg(test)]
thread_local! {
    static AUTHORIZED_MUTATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static POST_RECIPIENT_APPROVAL_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static POST_AUTHORIZED_MUTATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

struct MutationAuthorizationContext<'a> {
    evaluator: TrustPolicyEvaluator,
    trust_store: ReviewedTrustStore<'a>,
}

/// What the review settled, carried into the write that commits it.
///
/// A new document is encrypted before its recipient set can be reviewed, so the
/// ciphertext is what the review hands on. An existing document is mutated only
/// once the write is authorized under the lock, so the review hands on the
/// document it read instead.
enum ReviewedKvMutation<'a> {
    New(NewKvMutation),
    Existing(ExistingKvMutation<'a>),
}

struct NewKvMutation {
    encrypted: String,
    sid: uuid::Uuid,
}

struct ExistingKvMutation<'a> {
    existing: &'a KvEncContent,
    operation: KvMutationOperation,
}

pub fn set_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<'_, P>,
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
            let encrypted =
                set_kv_entry_with_recipients(existing_content, &entries, recipients, ctx)?;
            Ok(encrypted.as_str().to_owned())
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
    plan: &MutationWriteTrustPlan<'_, P>,
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
    plan: &MutationWriteTrustPlan<'_, P>,
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
    plan: &MutationWriteTrustPlan<'_, P>,
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
    plan: &MutationWriteTrustPlan<'_, P>,
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
    plan.review.ensure_current()?;
    plan.execution
        .key_ctx
        .inner()
        .enforce_signing_key_not_expired()?;
    let reviewed = review_kv_mutation(
        plan,
        create_operation,
        operation,
        &mut confirm_recipient_set,
    )?;
    let secrets_dir = plan.execution.ensured_secrets_directory()?;
    with_exclusive_locked_directory(secrets_dir.as_ref(), |locked_secrets_dir| {
        let encrypted =
            commit_kv_mutation(plan, reviewed, authorized_operation, locked_secrets_dir)?;
        plan.review
            .save_replacement_at(locked_secrets_dir, &encrypted)?;
        Ok(KvWriteOutcome {
            message: success_message.map(ToOwned::to_owned),
        })
    })
}

/// Settle what the mutation will write, prompting the operator where needed.
///
/// Nothing here holds the secrets directory lock, so a prompt that waits on an
/// answer does not stall other commands. What the review compares against is
/// still the state it was planned from, and a change made while the operator
/// was deciding is reported the moment the prompt returns.
fn review_kv_mutation<'a, P, F, ConfirmRecipientSet>(
    plan: &'a MutationWriteTrustPlan<'_, P>,
    create_operation: F,
    operation: KvMutationOperation,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<ReviewedKvMutation<'a>>
where
    P: WriteTrustPolicy,
    F: FnOnce(Option<&KvEncContent>, &KvRecipientSnapshot, &KvWriteContext<'_>) -> Result<String>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let Some(existing) = plan.review.existing_content() else {
        let new = review_new_kv_mutation(plan, create_operation, confirm_recipient_set)?;
        return Ok(ReviewedKvMutation::New(new));
    };
    review_existing_kv_mutation(plan, existing, operation, confirm_recipient_set)?;
    Ok(ReviewedKvMutation::Existing(ExistingKvMutation {
        existing,
        operation,
    }))
}

/// Commit the reviewed mutation with the secrets directory locked.
///
/// The target is confirmed to be the very entry the review read before anything
/// is written, and the authorization is re-derived from the trust store rather
/// than taken from the decision the review reached. A trust store that no
/// longer authorizes the mutation ends it here instead of prompting again.
///
/// The target is confirmed again once the replacement bytes exist, because the
/// work in between reads the artifact and produces the mutation from it. See
/// [`enforce_final_snapshot`].
fn commit_kv_mutation<P, D, AuthorizedOperation>(
    plan: &MutationWriteTrustPlan<'_, P>,
    reviewed: ReviewedKvMutation<'_>,
    authorized_operation: AuthorizedOperation,
    locked_secrets_dir: &D,
) -> Result<String>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
    AuthorizedOperation: FnOnce(&AuthorizedKvMutation<'_>) -> Result<String>,
{
    plan.review.ensure_target_current_at(locked_secrets_dir)?;
    match reviewed {
        ReviewedKvMutation::New(new) => commit_new_kv_mutation(plan, new, locked_secrets_dir),
        ReviewedKvMutation::Existing(existing) => {
            commit_existing_kv_mutation(plan, existing, authorized_operation, locked_secrets_dir)
        }
    }
}

fn review_new_kv_mutation<P, F, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<'_, P>,
    create_operation: F,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<NewKvMutation>
where
    P: WriteTrustPolicy,
    F: FnOnce(Option<&KvEncContent>, &KvRecipientSnapshot, &KvWriteContext<'_>) -> Result<String>,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let write_ctx = KvWriteContext::new(
        &plan.execution.member_handle,
        plan.execution.key_ctx.inner(),
    );
    let encrypted = create_operation(None, plan.review.recipients(), &write_ctx)?;
    let content = plan.review.encrypted_content(encrypted.clone());
    let sid = review_new_kv_recipient_set(plan, &content, confirm_recipient_set)?;
    run_post_recipient_approval_hook();
    Ok(NewKvMutation { encrypted, sid })
}

fn commit_new_kv_mutation<P, D>(
    plan: &MutationWriteTrustPlan<'_, P>,
    reviewed: NewKvMutation,
    locked_secrets_dir: &D,
) -> Result<String>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
{
    let NewKvMutation { encrypted, sid } = reviewed;
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

/// Decide whether an existing document may be mutated, prompting when the
/// output member set has not been approved yet.
fn review_existing_kv_mutation<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<'_, P>,
    existing: &KvEncContent,
    operation: KvMutationOperation,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<()>
where
    P: WriteTrustPolicy,
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
    let TrustDecision::ReviewRequired(requests) = decision else {
        return enforce_app_accepts_recipient_set(&app_outcome);
    };
    enforce_app_reviews_recipient_set(&requests, &app_outcome, &output)?;
    review_existing_recipient_set(plan, &output, &app_outcome, confirm_recipient_set)?;
    run_post_recipient_approval_hook();
    Ok(())
}

fn commit_existing_kv_mutation<P, D, AuthorizedOperation>(
    plan: &MutationWriteTrustPlan<'_, P>,
    reviewed: ExistingKvMutation<'_>,
    authorized_operation: AuthorizedOperation,
    locked_secrets_dir: &D,
) -> Result<String>
where
    P: WriteTrustPolicy,
    D: DirectoryFd,
    AuthorizedOperation: FnOnce(&AuthorizedKvMutation<'_>) -> Result<String>,
{
    let ExistingKvMutation {
        existing,
        operation,
    } = reviewed;
    let artifact = KvEncArtifact::parse(existing.as_str())?;
    let verified = artifact.verify(plan.options.operation_options())?;
    let recipients = build_authorized_recipient_keys(plan)?;
    let current = load_mutation_authorization(plan, &recipients)?;
    let decision = current.evaluator.evaluate_kv_mutation(
        &verified,
        &recipients,
        &plan.execution.key_ctx,
        operation,
        plan.options.operation_options(),
    )?;
    let TrustDecision::Trusted(authorized) = decision else {
        return Err(build_mutation_review_changed_error());
    };
    let encrypted = execute_authorized_operation(&authorized, authorized_operation)?;
    enforce_final_snapshot(plan, locked_secrets_dir, &current.trust_store)?;
    Ok(encrypted)
}

fn build_authorized_recipient_keys<P>(plan: &MutationWriteTrustPlan<'_, P>) -> Result<RecipientKeys>
where
    P: WriteTrustPolicy,
{
    let recipients = plan.review.recipients();
    RecipientKeys::from_verified_parts(
        recipients.member_handles.clone(),
        recipients.verified_members.clone(),
    )
}

fn load_mutation_authorization<'a, P>(
    plan: &MutationWriteTrustPlan<'a, P>,
    recipients: &RecipientKeys,
) -> Result<MutationAuthorizationContext<'a>>
where
    P: WriteTrustPolicy,
{
    let members = CurrentMemberSnapshot::from_recipient_keys(recipients)?;
    let keystore = plan
        .execution
        .require_local_keystore_access("KV mutation")?;
    let home = plan.execution.optional_local_state_home().ok_or_else(|| {
        Error::build_invalid_operation_error(
            "KV mutation requires a fixed local-state home capability".to_string(),
        )
    })?;
    let trust_dir = plan.execution.opened_trust_directory()?;
    let loaded = load_verified_local_trust_store(
        home,
        trust_dir.map(Arc::as_ref),
        plan.execution.member_handle.clone(),
        Some(keystore),
    )?;
    let protected = loaded.as_ref().map(|store| store.protected().clone());
    let store = loaded.map(|store| store.into_store());
    Ok(MutationAuthorizationContext {
        evaluator: TrustPolicyEvaluator::new(members, store),
        trust_store: ReviewedTrustStore::from_protected(
            plan.execution,
            protected,
            KV_TRUST_STORE_CHANGED_MESSAGE,
        ),
    })
}

fn review_new_kv_recipient_set<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<'_, P>,
    content: &crate::format::content::EncContent,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<uuid::Uuid>
where
    P: WriteTrustPolicy,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    let evidence = artifact_recipient_evidence(content)?;
    let sid = evidence.recipient_set.sid();
    review_artifact_recipient_set_output(
        TrustExecutionContext {
            options: &plan.options,
            execution: plan.execution,
        },
        ArtifactRecipientSetReviewInput {
            trust_ctx: &plan.trust_context,
            recipient_set: &evidence.recipient_set,
            capability: P::CAPABILITY,
            context_label: "kv output member set",
        },
        |outcome, context_label| {
            let confirmed = confirm_recipient_set(outcome, context_label)?;
            plan.review.ensure_current()?;
            Ok(confirmed)
        },
    )?;
    Ok(sid)
}

fn review_existing_recipient_set<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<'_, P>,
    output: &ArtifactRecipientSet,
    outcome: &ArtifactRecipientTrustOutcome,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<()>
where
    P: WriteTrustPolicy,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    review_artifact_recipient_set_output(
        TrustExecutionContext {
            options: &plan.options,
            execution: plan.execution,
        },
        ArtifactRecipientSetReviewInput {
            trust_ctx: &plan.trust_context,
            recipient_set: output,
            capability: P::CAPABILITY,
            context_label: "kv output member set",
        },
        |review_outcome, context_label| {
            if review_outcome != outcome {
                return Err(build_mutation_review_changed_error());
            }
            let confirmed = confirm_recipient_set(review_outcome, context_label)?;
            plan.review.ensure_current()?;
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

/// Confirm nothing the write rests on moved while the write was being produced.
///
/// This repeats the target check the commit already ran when it took the lock,
/// and the repetition is the point: the two calls sit either side of the work
/// that turns the reviewed document into the bytes about to replace it. That
/// work re-reads the artifact, derives the authorization from the trust store
/// and, for an existing document, runs the authorized mutation itself, and the
/// lock does not stop any of it from seeing a target that changed in between —
/// a write of the file by anything that ignores the lock lands exactly there.
/// Checking only once, at either end, would let those bytes be written over a
/// document nobody reviewed.
///
/// The member set and the trust store are read from outside the lock
/// altogether, so they are confirmed here for the same reason.
fn enforce_final_snapshot<P, D>(
    plan: &MutationWriteTrustPlan<'_, P>,
    locked_secrets_dir: &D,
    trust_store: &ReviewedTrustStore<'_>,
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
