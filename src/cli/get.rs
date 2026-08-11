// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! get command - get and decrypt key-value entries from default kv-enc file

use clap::Args;

use crate::cli::common::command::{
    ensure_reviewed_artifact_unchanged, resolve_options_with_read_trust_allowances,
    run_read_command_with_recovery, ReadCommandContext, ReadCommandLabels,
};
use crate::cli::common::output::kv::{print_kv_read_result, KvReadResult};
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, KvStoreNameOption, MemberHandleOption,
    SigningOutputOptions,
};
use kapsaro_core::api::kv::{KvEncArtifact, KvReadOperation};
use kapsaro_core::api::trust::TrustDecision;
use kapsaro_core::cli_api::app::context::execution::{
    resolve_read_execution, resolve_read_trust_evaluator,
};
use kapsaro_core::cli_api::app::errors::build_kv_key_not_found_error;
use kapsaro_core::cli_api::app::kv::query::{evaluate_kv_read_trust_plan, resolve_kv_read_path};
use kapsaro_core::cli_api::app::trust::evaluate_kv_after_cli_review;
use kapsaro_core::cli_api::app::trust::GetPolicy;
use kapsaro_core::{Error, Result};

#[derive(Args)]
pub(crate) struct GetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub allow_non_member: AllowNonMemberOption,

    /// Output all entries
    #[arg(long, short = 'a')]
    pub all: bool,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// Output in KEY="VALUE" format
    #[arg(long, short = 'k')]
    pub with_key: bool,

    /// Key name to retrieve
    pub key: Option<String>,
}

pub(crate) fn run(args: GetArgs) -> Result<()> {
    let read_mode = resolve_get_read_mode(args.all, args.key.as_deref())?;
    let options = resolve_options_with_read_trust_allowances(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        args.allow_non_member.allow_non_member,
    )?;
    let artifact_path = resolve_kv_read_path(&options, args.store.name.as_deref())?;
    let artifact = KvEncArtifact::load(&artifact_path)?;
    let verified = artifact.verify(options.operation_options())?;
    let operation = match &read_mode {
        KvReadMode::All => KvReadOperation::Entries,
        KvReadMode::Single(key) => KvReadOperation::Entry((*key).to_string()),
    };
    let kv_map = run_read_command_with_recovery(
        &options,
        args.member.member_handle.clone(),
        ReadCommandLabels {
            context: "get signer",
            subject: "signer",
            workspace_purpose: "kv access",
            allow_non_member: options.allow_non_member,
        },
        |ssh_ctx| {
            let execution =
                resolve_read_execution(&options, args.member.member_handle.clone(), None, ssh_ctx)?;
            let trust = evaluate_kv_read_trust_plan::<GetPolicy>(&options, &execution, &verified)?;
            Ok(ReadCommandContext::new(execution, trust))
        },
        |context| {
            let current_artifact = KvEncArtifact::load(&artifact_path)?;
            ensure_reviewed_artifact_unchanged(
                artifact.as_str(),
                current_artifact.as_str(),
                "KV get authorization",
            )?;
            let current = current_artifact.verify(options.operation_options())?;
            let evaluator = resolve_read_trust_evaluator(&options, &context.execution)?;
            let values = match evaluate_kv_after_cli_review(
                &evaluator,
                &verified,
                &current,
                &context.execution.key_ctx,
                operation.clone(),
                context.signer_outcome(),
                options.operation_options(),
            )? {
                TrustDecision::Trusted(trusted) => match &read_mode {
                    KvReadMode::All => trusted.decrypt_entries()?,
                    KvReadMode::Single(key) => {
                        let value = trusted.decrypt_entry().map_err(|error| {
                            build_kv_key_not_found_error(error, &artifact_path, key)
                        })?;
                        std::collections::BTreeMap::from([((*key).to_string(), value)])
                    }
                },
                TrustDecision::ReviewRequired(_) => return Err(trust_state_changed_error()),
            };
            let disclosed = match evaluate_kv_after_cli_review(
                &evaluator,
                &verified,
                &current,
                &context.execution.key_ctx,
                KvReadOperation::List,
                context.signer_outcome(),
                options.operation_options(),
            )? {
                TrustDecision::Trusted(trusted) => trusted.list_entry_keys()?,
                TrustDecision::ReviewRequired(_) => return Err(trust_state_changed_error()),
            };
            Ok(KvReadResult { values, disclosed })
        },
    )?;

    print_kv_read_result(
        &kv_map,
        if args.all { None } else { args.key.as_deref() },
        args.common.json.json,
        args.with_key,
    )
}

#[derive(Clone, Copy)]
enum KvReadMode<'a> {
    All,
    Single(&'a str),
}

fn trust_state_changed_error() -> Error {
    Error::build_verification_error(
        "E_TRUST_REVIEW_REQUIRED".to_string(),
        "Trust state changed while reviewing the KV artifact".to_string(),
    )
}

fn resolve_get_read_mode(all: bool, key: Option<&str>) -> Result<KvReadMode<'_>> {
    match (all, key) {
        (true, Some(_)) => Err(Error::build_invalid_operation_error(
            "--all and KEY argument cannot be used together",
        )),
        (true, None) => Ok(KvReadMode::All),
        (false, Some(key)) => Ok(KvReadMode::Single(key)),
        (false, None) => Err(Error::build_invalid_operation_error(
            "KEY argument is required (or use --all to get all entries)",
        )),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_get_test.rs"]
mod tests;
