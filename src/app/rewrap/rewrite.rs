// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Captured artifact rewrite executor for rewrap.

use crate::app::context::execution::ExecutionContext;
use crate::app::context::review::ReviewedTextFile;
use crate::feature::rewrap::{rewrap_content as rewrap_feature_content, RewrapRequest};
use crate::format::content::EncContent;
use crate::Result;

use super::types::{RewrapBatchPlan, RewrapBatchRequest, VerifiedPostPromotionRecipients};

pub(crate) struct RewrapRewriteContext<'a> {
    pub(crate) request: &'a RewrapBatchRequest,
    pub(crate) plan: &'a RewrapBatchPlan,
    pub(crate) execution: &'a ExecutionContext,
    pub(crate) post_promotion_members: &'a VerifiedPostPromotionRecipients,
}

pub(crate) fn build_rewritten_artifact(
    content: &EncContent,
    ctx: &RewrapRewriteContext<'_>,
) -> Result<String> {
    let rewrap_request = build_rewrap_request(ctx);
    rewrap_feature_content(content, &rewrap_request)
}

pub(crate) fn save_rewritten_artifact(captured: &ReviewedTextFile, rewritten: &str) -> Result<()> {
    captured.save_replacement(rewritten)?;
    Ok(())
}

fn build_rewrap_request<'a>(ctx: &'a RewrapRewriteContext<'a>) -> RewrapRequest<'a> {
    RewrapRequest {
        member_handle: ctx.execution.member_handle.as_str(),
        key_ctx: &ctx.execution.key_ctx,
        workspace_root: Some(ctx.plan.workspace_root.as_path()),
        target_members: Some(ctx.post_promotion_members.verified_members()),
        rotate_key: ctx.request.rotate_key,
        clear_disclosure_history: ctx.request.clear_disclosure_history,
        debug: ctx.request.options.verbose,
    }
}
