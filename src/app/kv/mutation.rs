// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::artifact::{kv_content_recipient_evidence, kv_recipient_evidence};
use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::review::{ensure_workspace_members_match_snapshot, ReviewedTextFile};
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::errors::build_kv_key_not_found_error;
use crate::app::trust::enforcement::enforce_write_input_artifact_recipients;
use crate::app::trust::review::{
    review_generated_artifact_recipient_set, GeneratedArtifactRecipientSetReview,
    TrustExecutionContext,
};
use crate::app::trust::{
    derive_self_sig_x, evaluate_signer_trust_with_proof, ArtifactRecipientTrustOutcome,
    CommandCapability, RecipientTrustOutcome, SignerTrustOutcome, TrustContext,
    WorkspaceMemberSnapshot, WriteRecipientTrustPlan, WriteTrustPolicy,
};
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot,
    KvWriteContext,
};
use crate::feature::kv::types::KvInputEntry;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::dotenv::{parse_dotenv, validate_dotenv_strict};
use crate::support::fs::lock;
use crate::support::limits::resolve_encrypted_artifact_read_limit;
use crate::{Error, Result};

use super::session::{load_existing_content, KvCommandSession, KvFileTarget};
use super::types::{KvImportResult, KvWriteOutcome};
use std::marker::PhantomData;

pub(crate) struct MutationWriteTrustPlan<P> {
    options: CommonCommandOptions,
    pub(crate) execution: ExecutionContext,
    pub(crate) signer_trust: Option<SignerTrustOutcome>,
    pub(crate) recipient_trust: RecipientTrustOutcome,
    trust_context: TrustContext,
    pub(crate) warnings: Vec<String>,
    review: MutationReviewSnapshot,
    verbose: bool,
    _policy: PhantomData<P>,
}

struct MutationReviewSnapshot {
    target: KvFileTarget,
    file: ReviewedKvFileState,
    file_snapshot: ReviewedTextFile,
    members: WorkspaceMemberSnapshot,
    recipients: KvRecipientSnapshot,
}

enum ReviewedKvFileState {
    Missing,
    Existing(KvEncContent),
}

impl ReviewedKvFileState {
    fn load(target: &KvFileTarget, allow_missing: bool) -> Result<Self> {
        match load_existing_content(target, allow_missing)? {
            Some(content) => Ok(Self::Existing(content)),
            None => Ok(Self::Missing),
        }
    }

    fn as_content(&self) -> Option<&KvEncContent> {
        match self {
            Self::Missing => None,
            Self::Existing(content) => Some(content),
        }
    }
}

impl MutationReviewSnapshot {
    fn build(
        target: KvFileTarget,
        workspace_members: WorkspaceMemberSnapshot,
        allow_missing: bool,
    ) -> Result<Self> {
        let recipients = build_recipient_snapshot(&workspace_members);
        let file = ReviewedKvFileState::load(&target, allow_missing)?;
        let file_snapshot = ReviewedTextFile::from_optional_content(
            &target.file_path,
            file.as_content()
                .map(|content| content.as_str().to_string()),
            "KV file",
            resolve_encrypted_artifact_read_limit(&target.file_path),
        );
        Ok(Self {
            target,
            file,
            file_snapshot,
            members: workspace_members,
            recipients,
        })
    }

    fn ensure_current(&self, verbose: bool) -> Result<()> {
        self.ensure_members_match(verbose)?;
        self.ensure_file_matches()
    }

    fn ensure_members_match(&self, verbose: bool) -> Result<()> {
        ensure_workspace_members_match_snapshot(
            &self.target.workspace_root.root_path,
            &self.members,
            verbose,
            "KV active members changed since review and must be reviewed again.",
        )
    }

    fn ensure_file_matches(&self) -> Result<()> {
        self.file_snapshot.ensure_current()
    }

    fn existing_content(&self) -> Option<&KvEncContent> {
        self.file.as_content()
    }
}

pub(crate) fn set_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
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
            let result = set_kv_entry_with_recipients(existing_content, &entries, recipients, ctx)?;
            Ok(result.encrypted.as_str().to_owned())
        },
        confirm_recipient_set,
    )
}

pub(crate) fn unset_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
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
            let kv_content = existing_content.ok_or_else(|| Error::Config {
                message: "File content is required".to_string(),
            })?;
            unset_kv_entry_with_recipients(kv_content, key, recipients, ctx)
                .map_err(|e| build_kv_key_not_found_error(e, &plan.review.target.file_path, key))
        },
        confirm_recipient_set,
    )
}

pub(crate) fn import_kv_command_with_recipient_set_confirmation<P, ConfirmRecipientSet>(
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

pub(crate) fn resolve_mutation_write_plan<P>(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    file_name: Option<&str>,
    allow_missing: bool,
    ssh_ctx: Option<SshSigningContextResolution>,
) -> Result<MutationWriteTrustPlan<P>>
where
    P: WriteTrustPolicy,
{
    let command = KvCommandSession::resolve_write(options, member_handle, file_name, ssh_ctx)?;
    let recipient_review = WriteRecipientTrustPlan::<P>::load(
        options,
        &command.target.workspace_root.root_path,
        &command.execution.member_handle,
        Some(derive_self_sig_x(&command.execution.key_ctx.signing_key)),
        options.verbose,
    )?;
    let review = MutationReviewSnapshot::build(
        command.target,
        recipient_review.workspace_members().clone(),
        allow_missing,
    )?;
    let signer_trust = evaluate_signer_trust(
        review.existing_content(),
        recipient_review.trust_context(),
        options.verbose,
        P::CAPABILITY,
    )?;
    let mut warnings = command.warnings;
    warnings.extend(recipient_review.warnings().iter().cloned());

    Ok(MutationWriteTrustPlan {
        options: options.clone(),
        execution: command.execution,
        signer_trust,
        recipient_trust: recipient_review.recipient_trust().clone(),
        trust_context: recipient_review.trust_context().clone(),
        warnings,
        review,
        verbose: options.verbose,
        _policy: PhantomData,
    })
}

fn execute_kv_mutation<P, F>(
    plan: &MutationWriteTrustPlan<P>,
    success_message: Option<&str>,
    operation: F,
    confirm_recipient_set: impl FnMut(&ArtifactRecipientTrustOutcome, &str) -> Result<bool>,
) -> Result<KvWriteOutcome>
where
    P: WriteTrustPolicy,
    F: FnOnce(Option<&KvEncContent>, &KvRecipientSnapshot, &KvWriteContext<'_>) -> Result<String>,
{
    let file_path = plan.review.target.file_path.clone();
    lock::with_file_lock(&file_path, || {
        plan.review.ensure_current(plan.verbose)?;
        enforce_key_not_expired_for_signing(&plan.execution.key_ctx.expires_at)?;
        let write_ctx = KvWriteContext::new(
            &plan.execution.member_handle,
            &plan.execution.key_ctx,
            plan.verbose,
        );
        let encrypted = operation(
            plan.review.existing_content(),
            &plan.review.recipients,
            &write_ctx,
        )?;
        let content = KvEncContent::new_unchecked(encrypted.clone());
        let evidence = kv_content_recipient_evidence(&content)?;
        let mut warnings = Vec::new();
        review_generated_artifact_recipient_set(
            TrustExecutionContext {
                options: &plan.options,
                execution: &plan.execution,
                warnings: &[],
            },
            GeneratedArtifactRecipientSetReview {
                trust_ctx: &plan.trust_context,
                signer_kid: plan.execution.key_ctx.kid.as_str(),
                recipient_set: &evidence.recipient_set,
                capability: P::CAPABILITY,
                context_label: "kv output member set",
            },
            &mut |new_warnings| warnings.extend_from_slice(new_warnings),
            confirm_recipient_set,
        )?;
        plan.review.file_snapshot.save_replacement(&encrypted)?;
        Ok(KvWriteOutcome {
            message: success_message.map(ToOwned::to_owned),
            warnings,
        })
    })
}

fn evaluate_signer_trust(
    reviewed_file: Option<&KvEncContent>,
    trust_ctx: &TrustContext,
    verbose: bool,
    capability: CommandCapability,
) -> Result<Option<SignerTrustOutcome>> {
    let Some(content) = reviewed_file else {
        return Ok(None);
    };

    let verified_doc = verify_kv_content(content, verbose)?;
    let recipient_evidence = kv_recipient_evidence(verified_doc.document())?;
    enforce_write_input_artifact_recipients(
        trust_ctx,
        verified_doc.proof().kid.as_str(),
        &recipient_evidence.recipient_set,
    )?;
    let outcome =
        evaluate_signer_trust_with_proof(trust_ctx, verified_doc.proof(), capability, &[])?;
    Ok(Some(outcome))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_kv_mutation_test.rs"]
mod tests;

fn build_recipient_snapshot(workspace_members: &WorkspaceMemberSnapshot) -> KvRecipientSnapshot {
    KvRecipientSnapshot {
        member_handles: workspace_members.member_handles().to_vec(),
        verified_members: workspace_members.verified_recipients().to_vec(),
    }
}
