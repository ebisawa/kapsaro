// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::app::errors::handle_kv_key_not_found_error;
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::kv::mutate::{set_kv_entry, unset_kv_entry, KvWriteContext};
use crate::format::content::KvEncContent;
use crate::format::kv::dotenv::{parse_dotenv, validate_dotenv_strict};
use crate::support::fs::{atomic, lock};
use crate::{Error, Result};

use super::session::{load_existing_content, KvFileTarget};
use super::types::{KvImportResult, KvWriteOutcome};

struct KvWriteRequest<'a> {
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&'a str>,
    allow_missing: bool,
    success_message: Option<&'a str>,
    ssh_ctx: Option<ResolvedSshSigner>,
}

pub(crate) fn set_kv_command(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    entries: Vec<(String, String)>,
    success_message: Option<&str>,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<KvWriteOutcome> {
    execute_kv_mutation(
        KvWriteRequest {
            options,
            member_id,
            file_name,
            allow_missing: true,
            success_message,
            ssh_ctx,
        },
        |existing_content, ctx, target| {
            let result = set_kv_entry(
                existing_content,
                &entries,
                target.workspace_root.root_path.as_path(),
                ctx,
            )?;
            Ok(result.encrypted.as_str().to_owned())
        },
    )
}

pub(crate) fn unset_kv_command(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    key: &str,
    success_message: Option<&str>,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<KvWriteOutcome> {
    execute_kv_mutation(
        KvWriteRequest {
            options,
            member_id,
            file_name,
            allow_missing: false,
            success_message,
            ssh_ctx,
        },
        |existing_content, ctx, target| {
            let kv_content = existing_content.ok_or_else(|| Error::Config {
                message: "File content is required".to_string(),
            })?;
            unset_kv_entry(kv_content, key, ctx)
                .map_err(|e| handle_kv_key_not_found_error(e, &target.file_path, key))
        },
    )
}

pub(crate) fn import_kv_command(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    dotenv_content: &str,
    success_message: Option<&str>,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<(KvWriteOutcome, usize)> {
    let result = import_kv_command_result(
        options,
        member_id,
        file_name,
        dotenv_content,
        success_message,
        ssh_ctx,
    )?;
    Ok((result.write_outcome, result.entry_count))
}

pub(crate) fn import_kv_command_result(
    options: CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    dotenv_content: &str,
    success_message: Option<&str>,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<KvImportResult> {
    validate_dotenv_strict(dotenv_content)?;
    let kv_map = parse_dotenv(dotenv_content)?;
    let entries: Vec<(String, String)> = kv_map.into_iter().collect();
    let entry_count = entries.len();
    let write_outcome = set_kv_command(
        options,
        member_id,
        file_name,
        entries,
        success_message,
        ssh_ctx,
    )?;
    Ok(KvImportResult {
        write_outcome,
        entry_count,
    })
}

fn execute_kv_mutation<F>(request: KvWriteRequest<'_>, operation: F) -> Result<KvWriteOutcome>
where
    F: FnOnce(Option<&KvEncContent>, &KvWriteContext, &KvFileTarget) -> Result<String>,
{
    let KvWriteRequest {
        options,
        member_id,
        file_name,
        allow_missing,
        success_message,
        ssh_ctx,
    } = request;
    let target = KvFileTarget::resolve(&options, file_name)?;
    let file_path = target.file_path.clone();
    lock::with_file_lock(&file_path, move || {
        let execution = ExecutionContext::resolve(&options, member_id, None, ssh_ctx)?;
        enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
        let write_ctx = build_kv_write_context(&options, execution);
        let existing_content = load_existing_content(&target, allow_missing)?;
        let encrypted = operation(existing_content.as_ref(), &write_ctx, &target)?;
        atomic::save_text(&target.file_path, &encrypted)?;
        Ok(KvWriteOutcome {
            message: success_message.map(ToOwned::to_owned),
        })
    })
}

fn build_kv_write_context(
    options: &CommonCommandOptions,
    execution: ExecutionContext,
) -> KvWriteContext {
    KvWriteContext::new(&execution.member_id, execution.key_ctx, options.verbose)
}
