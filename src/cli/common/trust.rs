// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI prompts for trust decisions.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::output::text::print_warning;
use crate::cli::common::output::trust::review::{
    format_candidate_review_lines, print_trust_review_line,
};
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use console::Style;
use secretenv_core::cli_api::app::context::options::CommonCommandOptions;
use secretenv_core::cli_api::app::trust::enforcement::ArtifactRecipientSetReview;
use secretenv_core::cli_api::app::trust::recovery::{
    build_trust_store_reset_plan, execute_trust_store_reset, requires_trust_store_reset,
    TrustStoreResetPlan,
};
use secretenv_core::cli_api::app::trust::{ArtifactRecipientTrustOutcome, TrustApprovalCandidate};
use secretenv_core::cli_api::presentation::kid::format_kid_display_lossy;
use secretenv_core::cli_api::presentation::path::format_path_relative_to_cwd;
use secretenv_core::cli_api::presentation::trust_document::RecipientHandleHint;
use secretenv_core::cli_api::presentation::tty;
use secretenv_core::{Error, Result};

pub(crate) fn confirm_signer_key_approval(
    candidate: &TrustApprovalCandidate,
    context_label: &str,
) -> Result<bool> {
    for line in format_signer_key_review_lines(candidate, context_label) {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Approve this key?", false)
}

pub(crate) fn confirm_non_member_acceptance(
    candidate: &TrustApprovalCandidate,
    context_label: &str,
    recipients: &[String],
) -> Result<bool> {
    for line in format_non_member_signer_review_lines(candidate, context_label, recipients) {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Accept this signed artifact once?", false)
}

pub(crate) fn confirm_recipient_approvals(
    candidates: &[TrustApprovalCandidate],
    context_label: &str,
) -> Result<Vec<TrustApprovalCandidate>> {
    let mut approved = Vec::new();
    for candidate in candidates {
        if confirm_recipient_key_approval(candidate, context_label)? {
            approved.push(candidate.clone());
        }
    }
    Ok(approved)
}

pub(crate) fn confirm_recipient_set_approval(
    outcome: &ArtifactRecipientTrustOutcome,
    context_label: &str,
) -> Result<bool> {
    let ArtifactRecipientTrustOutcome::NeedsManualApproval(review) = outcome else {
        return Ok(true);
    };

    for line in format_recipient_set_review_lines(review, context_label) {
        print_trust_review_line(&line);
    }
    prompt_yes_no(&recipient_set_review_prompt(review), false)
}

pub(crate) fn confirm_recipient_key_approval(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
) -> Result<bool> {
    for line in format_recipient_key_review_lines(candidate) {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Approve this key?", false)
}

pub(crate) fn confirm_member_key_approval(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
) -> Result<bool> {
    for line in format_member_key_review_lines(candidate, "member verify") {
        print_trust_review_line(&line);
    }
    prompt_yes_no("Approve this key?", false)
}

fn format_signer_key_review_lines(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
) -> Vec<String> {
    let mut lines = vec![
        "Key review required:".to_string(),
        String::new(),
        "This secret was signed by the member below.".to_string(),
        "Approve only if this public key belongs to that member.".to_string(),
        "If approved, this key will be remembered on this device for future checks.".to_string(),
        String::new(),
        "Before approving, confirm the fingerprint with the member through a trusted".to_string(),
        "channel, such as an in-person check, a signed message, or a fingerprint shared"
            .to_string(),
        "outside this repository.".to_string(),
        String::new(),
        "Key owner".to_string(),
    ];
    lines.extend(format_candidate_review_lines(candidate));
    lines
}

fn format_non_member_signer_review_lines(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
    recipients: &[String],
) -> Vec<String> {
    let mut lines = vec![
        "Signer outside active members:".to_string(),
        String::new(),
        "This secret was signed by a key that is not in the current active member list."
            .to_string(),
        "Accept only if you intentionally want to read this artifact once.".to_string(),
        "This decision will not save the signer key as trusted.".to_string(),
        String::new(),
        "Signer".to_string(),
    ];
    lines.extend(format_candidate_review_lines(candidate));
    if let Some(warning) = format_non_member_online_verification_warning(candidate) {
        lines.push(warning);
    }
    if !recipients.is_empty() {
        lines.push(String::new());
        lines.push("Current recipients".to_string());
        lines.extend(
            recipients
                .iter()
                .map(|recipient| format!("  - {}", recipient)),
        );
    }
    lines
}

fn format_non_member_online_verification_warning(
    candidate: &TrustApprovalCandidate,
) -> Option<String> {
    if !candidate.github_binding_configured
        || !candidate.online_verification_attempted
        || candidate.verified_github.is_some()
    {
        return None;
    }

    let message = candidate
        .online_verification_message
        .as_deref()
        .unwrap_or("online verification did not succeed");
    Some(format!(
        "Warning: GitHub online verification did not verify this signer: {}",
        message
    ))
}

fn format_recipient_key_review_lines(candidate: &TrustApprovalCandidate) -> Vec<String> {
    let mut lines = vec![
        "Key review required:".to_string(),
        String::new(),
        "This artifact references the member key below.".to_string(),
        "Approve only if this public key belongs to that member.".to_string(),
        "If approved, this key will be remembered on this device for future checks.".to_string(),
        String::new(),
        "Before approving, confirm the fingerprint with the member through a trusted".to_string(),
        "channel, such as an in-person check, a signed message, or a fingerprint shared"
            .to_string(),
        "outside this repository.".to_string(),
        String::new(),
        "Key owner".to_string(),
    ];
    lines.extend(format_candidate_review_lines(candidate));
    lines
}

fn format_member_key_review_lines(
    candidate: &TrustApprovalCandidate,
    _context_label: &str,
) -> Vec<String> {
    let mut lines = vec![
        "Key review required:".to_string(),
        String::new(),
        "You are approving the member key below.".to_string(),
        "Approve only if this public key belongs to that member.".to_string(),
        "If approved, this key will be remembered on this device for future checks.".to_string(),
        String::new(),
        "Before approving, confirm the fingerprint with the member through a trusted".to_string(),
        "channel, such as an in-person check, a signed message, or a fingerprint shared"
            .to_string(),
        "outside this repository.".to_string(),
        String::new(),
        "Key owner".to_string(),
    ];
    lines.extend(format_candidate_review_lines(candidate));
    lines
}

fn format_recipient_set_review_lines(
    review: &ArtifactRecipientSetReview,
    _context_label: &str,
) -> Vec<String> {
    let mut lines = recipient_set_review_intro(review.approved.is_some());
    if let Some(approved) = &review.approved {
        lines.push("Member changes".to_string());
        lines.extend(format_recipient_diff_lines(
            review.current.recipient_kids(),
            review.current.recipient_handle_hints(),
            &approved.recipient_kids,
            approved.recipient_handle_hints.as_deref().unwrap_or(&[]),
        ));
    } else {
        lines.push("Current members".to_string());
        lines.extend(format_recipient_lines(
            review.current.recipient_kids(),
            review.current.recipient_handle_hints(),
        ));
    }
    lines
}

fn recipient_set_review_prompt(review: &ArtifactRecipientSetReview) -> String {
    if review.approved.is_some() {
        "Update the trusted member set for this secret?".to_string()
    } else {
        "Trust this member set for this secret?".to_string()
    }
}

fn recipient_set_review_intro(changed: bool) -> Vec<String> {
    let mut lines = vec!["Secret sharing review required:".to_string(), String::new()];
    if changed {
        lines.extend([
            style_changed_message("This secret's member set differs from your last review."),
            style_changed_message("Approve only if this member change is expected."),
            style_changed_message("Approval updates the remembered member set on this device."),
        ]);
    } else {
        lines.extend([
            "This secret is shared with the members below.".to_string(),
            "Approve only if this member set is expected for this secret.".to_string(),
            "Approval is remembered on this device for future checks.".to_string(),
        ]);
    }
    lines.push(String::new());
    lines
}

fn style_changed_message(message: &str) -> String {
    Style::new()
        .yellow()
        .bold()
        .for_stderr()
        .apply_to(message)
        .to_string()
}

fn format_recipient_lines(kids: &[String], hints: &[RecipientHandleHint]) -> Vec<String> {
    let rows = kids
        .iter()
        .map(|kid| RecipientDisplayRow::new(kid, find_recipient_handle(kid, hints)))
        .collect::<Vec<_>>();
    format_member_key_rows(&rows)
}

#[derive(Clone)]
struct RecipientDisplayRow {
    member_handle: String,
    key_id: String,
}

impl RecipientDisplayRow {
    fn new(kid: &str, member_handle: String) -> Self {
        Self {
            member_handle,
            key_id: format_kid_display_lossy(kid),
        }
    }
}

fn format_member_key_rows(rows: &[RecipientDisplayRow]) -> Vec<String> {
    let member_width = rows
        .iter()
        .map(|row| row.member_handle.len())
        .max()
        .unwrap_or("member handle".len())
        .max("member handle".len());
    let mut lines = vec![format!(
        "  {:member_width$}  key id",
        "member handle",
        member_width = member_width
    )];
    lines.extend(rows.iter().map(|row| {
        format!(
            "  {:member_width$}  {}",
            row.member_handle,
            row.key_id,
            member_width = member_width
        )
    }));
    lines
}

fn format_recipient_diff_lines(
    current_kids: &[String],
    current_hints: &[RecipientHandleHint],
    approved_kids: &[String],
    approved_hints: &[RecipientHandleHint],
) -> Vec<String> {
    let current = build_recipient_rows_by_kid(current_kids, current_hints);
    let approved = build_recipient_rows_by_kid(approved_kids, approved_hints);
    let rows = build_recipient_diff_rows(&current, &approved);
    format_recipient_diff_rows(&rows)
}

fn build_recipient_rows_by_kid(
    kids: &[String],
    hints: &[RecipientHandleHint],
) -> BTreeMap<String, RecipientDisplayRow> {
    kids.iter()
        .map(|kid| {
            (
                kid.clone(),
                RecipientDisplayRow::new(kid, find_recipient_handle(kid, hints)),
            )
        })
        .collect()
}

fn build_recipient_diff_rows(
    current: &BTreeMap<String, RecipientDisplayRow>,
    approved: &BTreeMap<String, RecipientDisplayRow>,
) -> Vec<RecipientDiffRow> {
    let all_kids = current
        .keys()
        .chain(approved.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    all_kids
        .into_iter()
        .filter_map(|kid| match (current.get(&kid), approved.get(&kid)) {
            (Some(row), None) => Some(RecipientDiffRow::added(row.clone())),
            (None, Some(row)) => Some(RecipientDiffRow::removed(row.clone())),
            (Some(row), Some(_)) => Some(RecipientDiffRow::unchanged(row.clone())),
            (None, None) => None,
        })
        .collect()
}

struct RecipientDiffRow {
    status: RecipientDiffStatus,
    row: RecipientDisplayRow,
}

impl RecipientDiffRow {
    fn added(row: RecipientDisplayRow) -> Self {
        Self {
            status: RecipientDiffStatus::Added,
            row,
        }
    }

    fn removed(row: RecipientDisplayRow) -> Self {
        Self {
            status: RecipientDiffStatus::Removed,
            row,
        }
    }

    fn unchanged(row: RecipientDisplayRow) -> Self {
        Self {
            status: RecipientDiffStatus::Unchanged,
            row,
        }
    }
}

enum RecipientDiffStatus {
    Added,
    Removed,
    Unchanged,
}

impl RecipientDiffStatus {
    fn marker(&self) -> &'static str {
        match self {
            Self::Added => "+",
            Self::Removed => "-",
            Self::Unchanged => " ",
        }
    }

    fn style_line(&self, line: String) -> String {
        match self {
            Self::Added => Style::new().green().for_stderr().apply_to(line).to_string(),
            Self::Removed => Style::new().red().for_stderr().apply_to(line).to_string(),
            Self::Unchanged => line,
        }
    }
}

fn format_recipient_diff_rows(rows: &[RecipientDiffRow]) -> Vec<String> {
    let member_width = rows
        .iter()
        .map(|diff| diff.row.member_handle.len())
        .max()
        .unwrap_or("member handle".len())
        .max("member handle".len());
    let mut lines = vec![format!(
        "  change  {:member_width$}  key id",
        "member handle",
        member_width = member_width
    )];
    lines.extend(rows.iter().map(|diff| {
        let line = format!(
            "  {} {:member_width$}  {}",
            diff.status.marker(),
            diff.row.member_handle,
            diff.row.key_id,
            member_width = member_width
        );
        diff.status.style_line(line)
    }));
    lines
}

fn find_recipient_handle(kid: &str, hints: &[RecipientHandleHint]) -> String {
    hints
        .iter()
        .find(|hint| hint.kid == kid)
        .map(|hint| hint.recipient_handle.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn run_with_trust_store_reset_recovery<T, ResolveOwner, Run>(
    options: &CommonCommandOptions,
    resolve_owner_handle: ResolveOwner,
    mut run: Run,
) -> Result<T>
where
    ResolveOwner: Fn() -> Result<String>,
    Run: FnMut() -> Result<T>,
{
    let mut attempted_reset = false;
    loop {
        match run() {
            Ok(value) => return Ok(value),
            Err(error) if !attempted_reset && requires_trust_store_reset(&error) => {
                let owner_handle = resolve_owner_handle()?;
                recover_invalid_trust_store(options, &owner_handle, error)?;
                attempted_reset = true;
            }
            Err(error) => return Err(error),
        }
    }
}

fn recover_invalid_trust_store(
    options: &CommonCommandOptions,
    owner_handle: &str,
    error: Error,
) -> Result<()> {
    let plan = build_trust_store_reset_plan(options, owner_handle, error, tty::is_interactive())?;
    recover_prepared_trust_store(&plan, confirm_trust_store_reset)
}

fn recover_prepared_trust_store(
    plan: &TrustStoreResetPlan,
    confirm: impl FnOnce(&std::path::Path) -> Result<bool>,
) -> Result<()> {
    print_warning(&plan.warning_message);
    if !confirm(&plan.path)? {
        return Err(Error::build_invalid_operation_error(
            "Local trust store reset was declined".to_string(),
        ));
    }

    let outcome = execute_trust_store_reset(plan)?;
    eprintln!(
        "Deleted local trust store '{}'. Continuing with an empty trust cache.",
        format_path_relative_to_cwd(&outcome.path)
    );
    Ok(())
}

#[cfg(test)]
fn recover_invalid_trust_store_with_reader<R>(
    options: &CommonCommandOptions,
    owner_handle: &str,
    error: Error,
    reader: R,
    is_interactive: bool,
) -> Result<()>
where
    R: BufRead,
{
    let plan = build_trust_store_reset_plan(options, owner_handle, error, is_interactive)?;
    recover_prepared_trust_store(&plan, |path| {
        confirm_trust_store_reset_with_reader(path, reader)
    })
}

#[cfg(test)]
fn confirm_trust_store_reset_with_reader<R>(path: &std::path::Path, reader: R) -> Result<bool>
where
    R: BufRead,
{
    prompt_yes_no_with_reader(&trust_store_reset_prompt(path), false, reader)
}

fn confirm_trust_store_reset(path: &std::path::Path) -> Result<bool> {
    prompt_yes_no(&trust_store_reset_prompt(path), false)
}

fn trust_store_reset_prompt(path: &std::path::Path) -> String {
    format!(
        "Delete invalid local trust store '{}' and continue with an empty trust cache?",
        format_path_relative_to_cwd(path)
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_trust_recovery_test.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_trust_recipient_set_test.rs"]
mod recipient_set_tests;
