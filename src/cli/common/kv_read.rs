// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared read pipeline for the KV query commands (get, list, run).
//! Loads the artifact under review, runs the trust gate, and re-verifies before decryption.

use std::path::{Path, PathBuf};

use crate::cli::common::command::{
    ensure_reviewed_artifact_unchanged, resolve_read_execution_input,
    run_read_command_with_recovery, ReadCommandContext, ReadCommandLabels,
};
use kapsaro_core::api::key::KeyContext;
use kapsaro_core::api::kv::{
    KvEncArtifact, KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact,
};
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::trust::{KnownKeyReview, TrustDecision, TrustPolicyEvaluator};
use kapsaro_core::cli_api::app::context::execution::{
    resolve_read_trust_evaluator, ExecutionContext,
};
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::kv::query::load_kv_read_input;
use kapsaro_core::cli_api::app::trust::{
    evaluate_kv_after_cli_review, ReadArtifactTrustPlan, SignerTrustOutcome,
};
use kapsaro_core::{Error, Result};

/// Purpose reported when a KV read runs outside a workspace.
const KV_READ_PURPOSE: &str = "kv access";

/// One KV artifact opened for reading, together with the identity that reads it.
pub(crate) struct KvReadSession {
    options: CommonCommandOptions,
    artifact_path: PathBuf,
    artifact_file_name: String,
    artifact: KvEncArtifact,
    verified: VerifiedKvEncArtifact,
    execution: ExecutionContext,
}

/// The artifact as it stands after trust review, ready to authorize read operations.
pub(crate) struct KvReadReview<'a> {
    evaluator: TrustPolicyEvaluator,
    reviewed: &'a VerifiedKvEncArtifact,
    current: VerifiedKvEncArtifact,
    key_ctx: &'a KeyContext,
    signer_outcome: &'a SignerTrustOutcome,
    known_key_review: KnownKeyReview,
    options: OperationOptions,
}

impl KvReadSession {
    pub(crate) fn open(
        options: CommonCommandOptions,
        store_name: Option<&str>,
        member_handle: Option<String>,
    ) -> Result<Self> {
        let execution =
            resolve_read_execution_input(&options, member_handle, None, KV_READ_PURPOSE)?;
        let input = load_kv_read_input(&execution, store_name)?;
        let verified = input.artifact.verify(options.operation_options())?;
        Ok(Self {
            options,
            artifact_path: input.file_path,
            artifact_file_name: input.file_name,
            artifact: input.artifact,
            verified,
            execution,
        })
    }

    pub(crate) fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    pub(crate) fn allow_non_member(&self) -> bool {
        self.options.allow_non_member
    }

    /// Run one read under trust review, handing the reviewed artifact to `decrypt`.
    pub(crate) fn read<T, ResolvePlan, Decrypt>(
        &self,
        labels: ReadCommandLabels<'_>,
        authorization: &str,
        resolve_plan: ResolvePlan,
        mut decrypt: Decrypt,
    ) -> Result<T>
    where
        ResolvePlan: Fn(
            &CommonCommandOptions,
            &ExecutionContext,
            &VerifiedKvEncArtifact,
        ) -> Result<ReadArtifactTrustPlan>,
        Decrypt: FnMut(&KvReadReview<'_>) -> Result<T>,
    {
        run_read_command_with_recovery(
            &self.options,
            &self.execution,
            labels,
            |execution| {
                let trust = resolve_plan(&self.options, execution, &self.verified)?;
                Ok(ReadCommandContext::new(execution, trust))
            },
            |context| decrypt(&self.review_current_artifact(context, authorization)?),
        )
    }

    /// Reload the artifact so the decryption runs against the reviewed content.
    ///
    /// The reload goes through the secrets directory the execution bound to, so
    /// the document the decryption acts on and the member set the trust gate
    /// answered from come from the same tree.
    fn review_current_artifact<'a>(
        &'a self,
        context: &'a ReadCommandContext<'a>,
        authorization: &str,
    ) -> Result<KvReadReview<'a>> {
        let current_artifact = context
            .execution
            .reload_fixed_kv_artifact(&self.artifact_file_name)?;
        ensure_reviewed_artifact_unchanged(
            self.artifact.as_str(),
            current_artifact.as_str(),
            authorization,
        )?;
        Ok(KvReadReview {
            evaluator: resolve_read_trust_evaluator(context.execution)?,
            reviewed: &self.verified,
            current: current_artifact.verify(self.options.operation_options())?,
            key_ctx: &context.execution.key_ctx,
            signer_outcome: context.signer_outcome(),
            known_key_review: context.known_key_review(),
            options: self.options.operation_options(),
        })
    }
}

impl KvReadReview<'_> {
    pub(crate) fn authorize(&self, operation: KvReadOperation) -> Result<TrustedKvEncArtifact<'_>> {
        match evaluate_kv_after_cli_review(
            &self.evaluator,
            self.reviewed,
            &self.current,
            self.key_ctx,
            operation,
            self.signer_outcome,
            self.known_key_review,
            self.options,
        )? {
            TrustDecision::Trusted(trusted) => Ok(trusted),
            TrustDecision::ReviewRequired(_) => Err(trust_state_changed_error()),
        }
    }
}

fn trust_state_changed_error() -> Error {
    Error::build_verification_error(
        "E_TRUST_REVIEW_REQUIRED".to_string(),
        "Trust state changed while reviewing the KV artifact".to_string(),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_kv_read_test.rs"]
mod cli_common_kv_read_test;
