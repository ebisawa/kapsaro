// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::execution::ExecutionContext;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::app::member::mutation::promote_members;
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::rewrap::file::rewrap_file_document;
use crate::feature::rewrap::kv::rewrap_kv_document;
use crate::feature::rewrap::RewrapOptions;
use crate::format::content::{EncryptedContent, FileEncContent, KvEncContent};
use crate::format::token::TokenCodec;
use crate::support::fs::{atomic, load_text, lock};
use crate::Result;
use std::path::Path;

use super::types::{
    RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest, RewrapFileFailure, RewrapFileSuccess,
    SingleRewrapRequest,
};

/// Execute a batch rewrap over already planned files.
pub fn execute_rewrap_batch(
    request: &RewrapBatchRequest,
    plan: &RewrapBatchPlan,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<RewrapBatchOutcome> {
    if !request.accepted_promotions.is_empty() {
        promote_members(&plan.workspace_root, &request.accepted_promotions)?;
    }

    let execution =
        ExecutionContext::resolve(&request.options, request.member_id.clone(), None, ssh_ctx)?;
    enforce_key_not_expired_for_signing(&execution.key_ctx.expires_at)?;
    let mut processed_files = Vec::new();
    let mut failed_files = Vec::new();

    for file_path in &plan.file_paths {
        match process_rewrap_file(file_path, plan, &execution, request) {
            Ok(()) => processed_files.push(RewrapFileSuccess {
                output_path: file_path.clone(),
            }),
            Err(error) => failed_files.push(RewrapFileFailure {
                output_path: file_path.clone(),
                error_message: error.user_message().to_string(),
            }),
        }
    }

    Ok(RewrapBatchOutcome {
        processed_files,
        failed_files,
    })
}

fn process_rewrap_file(
    file_path: &Path,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
    request: &RewrapBatchRequest,
) -> Result<()> {
    let file_path_buf = file_path.to_path_buf();
    lock::with_file_lock(&file_path_buf, || {
        let content = load_text(file_path)?;
        let rewritten = match EncryptedContent::detect(content)? {
            EncryptedContent::FileEnc(file_content) => {
                rewrap_file_content(&file_content, plan, execution, request)?
            }
            EncryptedContent::KvEnc(kv_content) => {
                rewrap_kv_content(&kv_content, plan, execution, request)?
            }
        };

        atomic::save_text(file_path, &rewritten)
    })
}

fn rewrap_file_content(
    content: &FileEncContent,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
    request: &RewrapBatchRequest,
) -> Result<String> {
    let request = SingleRewrapRequest {
        member_id: &execution.member_id,
        key_ctx: &execution.key_ctx,
        workspace_root: Some(plan.workspace_root.as_path()),
        rotate_key: request.rotate_key,
        clear_disclosure_history: request.clear_disclosure_history,
        debug: request.options.verbose,
    };
    rewrap_file_content_with_request(content, &request)
}

fn rewrap_kv_content(
    content: &KvEncContent,
    plan: &RewrapBatchPlan,
    execution: &ExecutionContext,
    request: &RewrapBatchRequest,
) -> Result<String> {
    let request = SingleRewrapRequest {
        member_id: &execution.member_id,
        key_ctx: &execution.key_ctx,
        workspace_root: Some(plan.workspace_root.as_path()),
        rotate_key: request.rotate_key,
        clear_disclosure_history: request.clear_disclosure_history,
        debug: request.options.verbose,
    };
    rewrap_kv_content_with_request(content, &request)
}

pub fn rewrap_file_content_with_request(
    content: &FileEncContent,
    request: &SingleRewrapRequest<'_>,
) -> Result<String> {
    let options = build_single_rewrap_options(request, None);
    rewrap_file_document(
        &options,
        content,
        request.member_id,
        request.key_ctx,
        request.workspace_root,
    )
}

pub fn rewrap_kv_content_with_request(
    content: &KvEncContent,
    request: &SingleRewrapRequest<'_>,
) -> Result<String> {
    let options = build_single_rewrap_options(request, Some(TokenCodec::JsonJcs));
    rewrap_kv_document(
        &options,
        content,
        request.member_id,
        request.key_ctx,
        request.workspace_root,
    )
}

fn build_single_rewrap_options(
    request: &SingleRewrapRequest<'_>,
    token_codec: Option<TokenCodec>,
) -> RewrapOptions {
    RewrapOptions {
        rotate_key: request.rotate_key,
        clear_disclosure_history: request.clear_disclosure_history,
        token_codec,
        debug: request.debug,
    }
}
