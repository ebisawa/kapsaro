// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! list command - list all keys in default kv-enc file

use clap::Args;

use crate::cli::common::command::{
    ensure_reviewed_artifact_unchanged, resolve_options_with_read_trust_allowances,
    run_read_command_with_recovery, ReadCommandContext, ReadCommandLabels,
};
use crate::cli::common::output::kv::print_kv_key_list;
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, KvStoreNameOption, MemberHandleOption,
    SigningOutputOptions,
};
use kapsaro_core::api::kv::{KvEncArtifact, KvReadOperation};
use kapsaro_core::api::trust::TrustDecision;
use kapsaro_core::cli_api::app::context::execution::{
    resolve_read_execution, resolve_read_trust_evaluator,
};
use kapsaro_core::cli_api::app::kv::query::{evaluate_kv_read_trust_plan, resolve_kv_read_path};
use kapsaro_core::cli_api::app::trust::evaluate_kv_after_cli_review;
use kapsaro_core::cli_api::app::trust::ListPolicy;
use kapsaro_core::Result;

#[derive(Args)]
pub(crate) struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub allow_non_member: AllowNonMemberOption,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,
}

pub(crate) fn run(args: ListArgs) -> Result<()> {
    let options = resolve_options_with_read_trust_allowances(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        args.allow_non_member.allow_non_member,
    )?;
    let artifact_path = resolve_kv_read_path(&options, args.store.name.as_deref())?;
    let artifact = KvEncArtifact::load(&artifact_path)?;
    let verified = artifact.verify(options.operation_options())?;
    let keys_with_disclosed = run_read_command_with_recovery(
        &options,
        args.member.member_handle.clone(),
        ReadCommandLabels {
            context: "list signer",
            subject: "signer",
            workspace_purpose: "kv access",
            allow_non_member: options.allow_non_member,
        },
        |ssh_ctx| {
            let execution =
                resolve_read_execution(&options, args.member.member_handle.clone(), None, ssh_ctx)?;
            let trust = evaluate_kv_read_trust_plan::<ListPolicy>(&options, &execution, &verified)?;
            Ok(ReadCommandContext::new(execution, trust))
        },
        |context| {
            let current_artifact = KvEncArtifact::load(&artifact_path)?;
            ensure_reviewed_artifact_unchanged(
                artifact.as_str(),
                current_artifact.as_str(),
                "KV list authorization",
            )?;
            let current = current_artifact.verify(options.operation_options())?;
            let evaluator = resolve_read_trust_evaluator(&options, &context.execution)?;
            match evaluate_kv_after_cli_review(
                &evaluator,
                &verified,
                &current,
                &context.execution.key_ctx,
                KvReadOperation::List,
                context.signer_outcome(),
                options.operation_options(),
            )? {
                TrustDecision::Trusted(trusted) => trusted.list_entry_keys(),
                TrustDecision::ReviewRequired(_) => {
                    Err(kapsaro_core::Error::build_verification_error(
                        "E_TRUST_REVIEW_REQUIRED".to_string(),
                        "Trust state changed while reviewing the KV artifact".to_string(),
                    ))
                }
            }
        },
    )?;
    print_kv_key_list(&keys_with_disclosed, args.common.json.json)
}
