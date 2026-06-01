// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap feature - re-encryption for kv-enc and file-enc formats.

pub(crate) mod file;
pub(crate) mod file_op;
pub(crate) mod kv;
pub(crate) mod kv_op;

use crate::feature::context::crypto::CryptoContext;
use crate::format::content::EncContent;
use crate::format::token::TokenCodec;
use crate::model::common::WrapItem;
use crate::model::public_key_verified::VerifiedRecipientKey;
use crate::Result;
use tracing::debug;

/// Rewrap operation options.
#[derive(Debug, Clone)]
pub(crate) struct RewrapOptions {
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub token_codec: Option<TokenCodec>,
    pub debug: bool,
}

/// Context for rewrap operations that provides common functionality.
pub(crate) struct RewrapContext<'a> {
    options: &'a RewrapOptions,
    member_handle: &'a str,
    key_ctx: &'a CryptoContext,
    target_members: &'a [VerifiedRecipientKey],
}

/// Request for rewrapping a single encrypted artifact.
#[derive(Clone)]
pub struct RewrapRequest<'a> {
    pub member_handle: &'a str,
    pub key_ctx: &'a CryptoContext,
    pub target_members: Vec<VerifiedRecipientKey>,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub debug: bool,
}

impl<'a> RewrapContext<'a> {
    pub(crate) fn new(
        options: &'a RewrapOptions,
        member_handle: &'a str,
        key_ctx: &'a CryptoContext,
        target_members: &'a [VerifiedRecipientKey],
    ) -> Self {
        Self {
            options,
            member_handle,
            key_ctx,
            target_members,
        }
    }

    pub(crate) fn options(&self) -> &'a RewrapOptions {
        self.options
    }

    pub(crate) fn key_ctx(&self) -> &'a CryptoContext {
        self.key_ctx
    }

    pub(crate) fn member_handle(&self) -> &'a str {
        self.member_handle
    }

    pub(crate) fn target_members(&self) -> &'a [VerifiedRecipientKey] {
        self.target_members
    }
}

/// Trait for rewrap executors that can perform rewrap operations.
pub(crate) trait RewrapExecutor {
    /// Return the current recipients list from the encrypted file.
    /// - file-enc: recipient_handle fields from protected.wrap
    /// - kv-enc: result of extract_recipients_from_wrap(&wrap_data)
    fn current_recipients(&self) -> Vec<String>;

    /// Add recipients to the encrypted file (wrap only, MK/DEK unchanged).
    ///
    /// `recipients` are plain member handle strings.
    fn add_recipients(&mut self, recipients: &[String]) -> Result<()>;

    /// Rewrite wrap items for recipients whose target kid changed.
    fn rewrite_recipient_wraps(&mut self, recipients: &[String]) -> Result<()>;

    /// Remove recipients from the encrypted file.
    ///
    /// `recipients` are plain member handle strings.
    fn remove_recipients(&mut self, recipients: &[String]) -> Result<()>;

    /// Rotate master key / content key (full re-encryption).
    fn rotate_key(&mut self) -> Result<()>;

    /// Clear the disclosure history.
    fn clear_disclosure_history(&mut self) -> Result<()>;

    /// Finalize and sign the encrypted file, returning the final content.
    fn finalize(self) -> Result<String>;
}

pub(crate) trait VerifiedRewrapDocument {
    fn current_wrap_items(&self) -> &[WrapItem];
}

pub(crate) trait RewrapDocumentAdapter {
    type Content;
    type Verified: VerifiedRewrapDocument;
    type Executor<'ctx>: RewrapExecutor;

    fn verify_content(content: &Self::Content, debug: bool) -> Result<Self::Verified>;

    fn build_executor<'ctx>(
        verified: Self::Verified,
        ctx: &'ctx RewrapContext<'ctx>,
    ) -> Result<Self::Executor<'ctx>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RewrapOperationPlan {
    remove_recipients: Vec<String>,
    stale_recipient_handles: Vec<String>,
    add_recipients: Vec<String>,
    rotate_key: bool,
    clear_disclosure_history: bool,
}

/// Build the rewrap operation plan from current and target recipients.
pub(crate) fn build_rewrap_operation_plan(
    current_recipients: &[String],
    target_recipients: &[String],
    stale_recipients: &[String],
    options: &RewrapOptions,
) -> RewrapOperationPlan {
    let remove_recipients: Vec<String> = current_recipients
        .iter()
        .filter(|recipient| !target_recipients.contains(recipient))
        .cloned()
        .collect();
    let add_recipients = target_recipients
        .iter()
        .filter(|recipient| !current_recipients.contains(*recipient))
        .cloned()
        .collect();

    RewrapOperationPlan {
        remove_recipients,
        stale_recipient_handles: stale_recipients.to_vec(),
        add_recipients,
        rotate_key: options.rotate_key,
        clear_disclosure_history: options.clear_disclosure_history,
    }
}

/// Apply a rewrap operation plan and return the signed rewritten content.
pub(crate) fn rewrite_with_rewrap_operation_plan<E: RewrapExecutor>(
    mut executor: E,
    plan: RewrapOperationPlan,
    debug_enabled: bool,
) -> Result<String> {
    log_rewrap_operation_plan(&plan, debug_enabled);
    apply_rewrap_operation_plan(&mut executor, &plan, debug_enabled)?;
    log_rewrap_plan_step("finalize artifact", debug_enabled);
    executor.finalize()
}

fn apply_rewrap_operation_plan<E: RewrapExecutor>(
    executor: &mut E,
    plan: &RewrapOperationPlan,
    debug_enabled: bool,
) -> Result<()> {
    apply_recipient_step(
        executor,
        &plan.remove_recipients,
        "remove recipients",
        debug_enabled,
        RewrapExecutor::remove_recipients,
    )?;
    apply_recipient_step(
        executor,
        &plan.stale_recipient_handles,
        "rewrite stale recipient wraps",
        debug_enabled,
        RewrapExecutor::rewrite_recipient_wraps,
    )?;
    apply_recipient_step(
        executor,
        &plan.add_recipients,
        "add recipients",
        debug_enabled,
        RewrapExecutor::add_recipients,
    )?;
    apply_flag_step(plan.rotate_key, "rotate key", debug_enabled, || {
        executor.rotate_key()
    })?;
    apply_flag_step(
        plan.clear_disclosure_history,
        "clear disclosure history",
        debug_enabled,
        || executor.clear_disclosure_history(),
    )
}

fn apply_recipient_step<E, Apply>(
    executor: &mut E,
    recipients: &[String],
    label: &str,
    debug_enabled: bool,
    apply: Apply,
) -> Result<()>
where
    E: RewrapExecutor,
    Apply: FnOnce(&mut E, &[String]) -> Result<()>,
{
    if recipients.is_empty() {
        return Ok(());
    }
    log_rewrap_recipient_step(label, recipients.len(), debug_enabled);
    apply(executor, recipients)
}

fn apply_flag_step<Apply>(
    enabled: bool,
    label: &str,
    debug_enabled: bool,
    apply: Apply,
) -> Result<()>
where
    Apply: FnOnce() -> Result<()>,
{
    if !enabled {
        return Ok(());
    }
    log_rewrap_plan_step(label, debug_enabled);
    apply()
}

fn log_rewrap_operation_plan(plan: &RewrapOperationPlan, debug_enabled: bool) {
    if debug_enabled {
        debug!(
            "[REWRAP] plan: remove={}, stale={}, add={}, rotate_key={}, clear_disclosure_history={}",
            plan.remove_recipients.len(),
            plan.stale_recipient_handles.len(),
            plan.add_recipients.len(),
            plan.rotate_key,
            plan.clear_disclosure_history
        );
    }
}

fn log_rewrap_recipient_step(label: &str, count: usize, debug_enabled: bool) {
    if debug_enabled {
        debug!("[REWRAP] plan: {label} count={count}");
    }
}

fn log_rewrap_plan_step(label: &str, debug_enabled: bool) {
    if debug_enabled {
        debug!("[REWRAP] plan: {label}");
    }
}

pub(crate) fn collect_stale_recipient_handles(
    current_wrap: &[WrapItem],
    target_members: &[VerifiedRecipientKey],
) -> Vec<String> {
    target_members
        .iter()
        .filter_map(|member| {
            let protected = &member.document().protected;
            current_wrap
                .iter()
                .find(|wrap| wrap.recipient_handle == protected.subject_handle)
                .filter(|wrap| wrap.kid != protected.kid)
                .map(|_| protected.subject_handle.clone())
        })
        .collect()
}

pub(crate) fn rewrap_document_with_common_skeleton<A>(
    options: &RewrapOptions,
    content: &A::Content,
    member_handle: &str,
    key_ctx: &CryptoContext,
    target_members: &[VerifiedRecipientKey],
) -> Result<String>
where
    A: RewrapDocumentAdapter,
{
    let all_members = collect_target_member_handles(target_members);

    let verified = A::verify_content(content, options.debug)?;
    let stale_recipients =
        collect_stale_recipient_handles(verified.current_wrap_items(), target_members);

    let ctx = RewrapContext::new(options, member_handle, key_ctx, target_members);
    let executor = A::build_executor(verified, &ctx)?;
    let plan = build_rewrap_operation_plan(
        &executor.current_recipients(),
        &all_members,
        &stale_recipients,
        options,
    );
    rewrite_with_rewrap_operation_plan(executor, plan, options.debug)
}

fn collect_target_member_handles(target_members: &[VerifiedRecipientKey]) -> Vec<String> {
    let mut member_handles = target_members
        .iter()
        .map(|member| member.document().protected.subject_handle.clone())
        .collect::<Vec<_>>();
    member_handles.sort();
    member_handles
}

pub fn rewrap_content(content: &EncContent, request: &RewrapRequest<'_>) -> Result<String> {
    let options = RewrapOptions {
        rotate_key: request.rotate_key,
        clear_disclosure_history: request.clear_disclosure_history,
        token_codec: match content {
            EncContent::FileEnc(_) => None,
            EncContent::KvEnc(_) => Some(TokenCodec::JsonJcs),
        },
        debug: request.debug,
    };

    match content {
        EncContent::FileEnc(file_content) => file::rewrap_file_document(
            &options,
            file_content,
            request.member_handle,
            request.key_ctx,
            &request.target_members,
        ),
        EncContent::KvEnc(kv_content) => kv::rewrap_kv_document(
            &options,
            kv_content,
            request.member_handle,
            request.key_ctx,
            &request.target_members,
        ),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/feature_rewrap_common_test.rs"]
mod common_tests;
