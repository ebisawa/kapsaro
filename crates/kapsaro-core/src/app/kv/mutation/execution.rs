// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV mutation execution after review.
//! Rechecks snapshots, performs the feature write, and persists trust before replacement.

use crate::app::errors::build_kv_key_not_found_error;
use crate::app::trust::review::{
    review_artifact_output_recipient_set, ArtifactOutputRecipientSetReviewInput,
};
use crate::app::trust::{ArtifactRecipientTrustOutcome, WriteTrustPolicy};
use crate::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot,
    KvWriteContext,
};
use crate::format::content::KvEncContent;
use crate::format::kv::dotenv::{parse_dotenv, validate_dotenv_strict};
use crate::support::fs::lock;
use crate::{Error, Result};

use super::super::types::{KvImportResult, KvInputEntry, KvWriteOutcome};
use super::plan::MutationWriteTrustPlan;

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
    execute_kv_mutation(
        plan,
        success_message,
        |existing_content, recipients, ctx| {
            let entries = to_feature_entries(entries);
            let result = set_kv_entry_with_recipients(existing_content, &entries, recipients, ctx)?;
            Ok(result.encrypted.as_str().to_owned())
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

fn execute_kv_mutation<P, F>(
    plan: &MutationWriteTrustPlan<P>,
    success_message: Option<&str>,
    operation: F,
    mut confirm_recipient_set: impl FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
) -> Result<KvWriteOutcome>
where
    P: WriteTrustPolicy,
    F: FnOnce(Option<&KvEncContent>, &KvRecipientSnapshot, &KvWriteContext<'_>) -> Result<String>,
{
    let file_path = plan.review.target().file_path.clone();
    lock::with_file_lock(&file_path, || {
        plan.review.ensure_current(plan.verbose)?;
        plan.execution.key_ctx.enforce_signing_key_not_expired()?;
        let write_ctx = KvWriteContext::new(
            &plan.execution.member_handle,
            &plan.execution.key_ctx,
            plan.verbose,
        );
        let encrypted = operation(
            plan.review.existing_content(),
            plan.review.recipients(),
            &write_ctx,
        )?;
        let content = plan.review.encrypted_content(encrypted.clone());
        let mut warnings = Vec::new();
        review_kv_output_recipient_set(plan, &content, &mut warnings, &mut confirm_recipient_set)?;
        plan.review.save_replacement(&encrypted)?;
        Ok(KvWriteOutcome {
            message: success_message.map(ToOwned::to_owned),
            warnings,
        })
    })
}

fn review_kv_output_recipient_set<P, ConfirmRecipientSet>(
    plan: &MutationWriteTrustPlan<P>,
    content: &crate::format::content::EncContent,
    warnings: &mut Vec<String>,
    confirm_recipient_set: &mut ConfirmRecipientSet,
) -> Result<()>
where
    P: WriteTrustPolicy,
    ConfirmRecipientSet: FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
{
    review_artifact_output_recipient_set(
        ArtifactOutputRecipientSetReviewInput {
            options: &plan.options,
            execution: &plan.execution,
            trust_ctx: &plan.trust_context,
            content,
            capability: P::CAPABILITY,
            context_label: "kv output member set",
        },
        warnings,
        confirm_recipient_set,
    )
}

fn to_feature_entries(entries: Vec<KvInputEntry>) -> Vec<crate::feature::kv::types::KvInputEntry> {
    entries
        .into_iter()
        .map(KvInputEntry::into_feature)
        .collect()
}
