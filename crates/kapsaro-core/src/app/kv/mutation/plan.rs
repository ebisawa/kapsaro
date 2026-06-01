// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV mutation planning and write trust evaluation.
//! Builds the immutable review snapshot consumed by mutation execution.

use std::marker::PhantomData;

use crate::app::context::execution::{
    evaluate_selected_decryption_key_expiry, ExecutionContext, SelectedDecryptionKeyExpiry,
};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::SshSigningContextResolution;
use crate::app::trust::enforcement::enforce_write_input_artifact_recipients;
use crate::app::trust::{
    evaluate_signer_trust_with_proof, push_signature_verification_warnings, CommandCapability,
    RecipientTrustOutcome, SignerTrustOutcome, TrustContext, WriteRecipientTrustPlan,
    WriteTrustPolicy,
};
use crate::feature::envelope::wrap_set::WrapSet;
use crate::feature::trust::recipient_sets::kv_recipient_evidence;
use crate::feature::verify::kv::signature::verify_kv_content_for_operation;
use crate::format::content::KvEncContent;
use crate::support::warning::push_unique_warning;
use crate::Result;

use super::super::session::KvCommandSession;
use super::snapshot::MutationReviewSnapshot;

pub struct MutationWriteTrustPlan<P> {
    pub(super) options: CommonCommandOptions,
    pub execution: ExecutionContext,
    pub signer_trust: Option<SignerTrustOutcome>,
    pub recipient_trust: RecipientTrustOutcome,
    pub(crate) trust_context: TrustContext,
    pub warnings: Vec<String>,
    pub(super) review: MutationReviewSnapshot,
    pub(super) verbose: bool,
    _policy: PhantomData<P>,
}

pub fn resolve_mutation_write_plan<P>(
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
    let operation_options = options.operation_options();
    let recipient_review = WriteRecipientTrustPlan::<P>::load(
        options,
        &command.target.workspace_root.root_path,
        &command.execution.member_handle,
        Some(command.execution.key_ctx.self_signature_public_key_x()),
        Some(command.execution.key_ctx.local_key_identity()),
        options.debug,
    )?;
    let review = MutationReviewSnapshot::build(
        command.target,
        recipient_review.workspace_members().clone(),
        allow_missing,
    )?;
    let mut warnings = command.warnings;
    let existing_key_expiry = evaluate_existing_decryption_key_expiry(
        review.existing_content(),
        &command.execution,
        operation_options.allow_expired_key(),
        operation_options.debug(),
    )?;
    let signer_trust = evaluate_signer_trust(
        review.existing_content(),
        recipient_review.trust_context(),
        existing_key_expiry
            .as_ref()
            .map(|expiry| &expiry.key_identity),
        operation_options.debug(),
        operation_options.allow_expired_key(),
        P::CAPABILITY,
        &mut warnings,
    )?;
    if let Some(warning) = existing_key_expiry.and_then(|expiry| expiry.warning) {
        push_unique_warning(&mut warnings, warning);
    }
    warnings.extend(recipient_review.warnings().iter().cloned());

    Ok(MutationWriteTrustPlan {
        options: options.clone(),
        execution: command.execution,
        signer_trust,
        recipient_trust: recipient_review.recipient_trust().clone(),
        trust_context: recipient_review.trust_context().clone(),
        warnings,
        review,
        verbose: operation_options.debug(),
        _policy: PhantomData,
    })
}

fn evaluate_existing_decryption_key_expiry(
    reviewed_file: Option<&KvEncContent>,
    execution: &ExecutionContext,
    allow_expired_key: bool,
    debug: bool,
) -> Result<Option<SelectedDecryptionKeyExpiry>> {
    let Some(content) = reviewed_file else {
        return Ok(None);
    };
    let doc = content.parse()?;
    let wrap_set = WrapSet::parse(&doc.wrap().wrap, "Document")?;
    evaluate_selected_decryption_key_expiry(execution, &wrap_set, allow_expired_key, debug)
        .map(Some)
}

fn evaluate_signer_trust(
    reviewed_file: Option<&KvEncContent>,
    trust_ctx: &TrustContext,
    local_key_identity: Option<&crate::feature::context::crypto::LocalKeyIdentity>,
    verbose: bool,
    allow_expired_key: bool,
    capability: CommandCapability,
    warnings: &mut Vec<String>,
) -> Result<Option<SignerTrustOutcome>> {
    let Some(content) = reviewed_file else {
        return Ok(None);
    };

    let verified_doc = verify_kv_content_for_operation(content, verbose, allow_expired_key)?;
    push_signature_verification_warnings(warnings, verified_doc.proof(), local_key_identity)?;
    let recipient_evidence = kv_recipient_evidence(verified_doc.document())?;
    enforce_write_input_artifact_recipients(trust_ctx, &recipient_evidence.recipient_set)?;
    let outcome =
        evaluate_signer_trust_with_proof(trust_ctx, verified_doc.proof(), capability, &[])?;
    Ok(Some(outcome))
}
