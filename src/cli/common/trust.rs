// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI prompts for trust decisions.

use std::io::BufRead;

use crate::app::context::options::CommonCommandOptions;
use crate::app::trust::TrustApprovalCandidate;
use crate::cli::common::output::trust::review::print_candidate_review;
use crate::cli::common::prompt::{prompt_yes_no, prompt_yes_no_with_reader};
use crate::io::trust::paths::trust_store_file_path;
use crate::support::path::display_path_relative_to_cwd;
use crate::support::tty;
use crate::{Error, Result};

pub(crate) fn confirm_known_key_approval(
    candidate: &TrustApprovalCandidate,
    context_label: &str,
) -> Result<bool> {
    eprintln!(
        "Trust review for '{}' ({}):",
        candidate.member_id, context_label
    );
    print_candidate_review(candidate);
    prompt_yes_no("Approve this key and add it to local trust store?", false)
}

pub(crate) fn confirm_non_member_acceptance(
    candidate: &TrustApprovalCandidate,
    context_label: &str,
    recipients: &[String],
) -> Result<bool> {
    eprintln!(
        "Non-member acceptance for '{}' ({}):",
        candidate.member_id, context_label
    );
    print_candidate_review(candidate);
    if !recipients.is_empty() {
        eprintln!("  Current recipients: {}", recipients.join(", "));
    }
    prompt_yes_no("Accept this artifact one time only?", false)
}

pub(crate) fn confirm_recipient_approvals(
    candidates: &[TrustApprovalCandidate],
    context_label: &str,
) -> Result<Vec<TrustApprovalCandidate>> {
    let mut approved = Vec::new();
    for candidate in candidates {
        if confirm_known_key_approval(candidate, context_label)? {
            approved.push(candidate.clone());
        }
    }
    Ok(approved)
}

pub(crate) fn run_with_trust_store_reset_recovery<T, ResolveOwner, Run>(
    options: &CommonCommandOptions,
    resolve_owner_member_id: ResolveOwner,
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
                let owner_member_id = resolve_owner_member_id()?;
                recover_invalid_trust_store(options, &owner_member_id, error)?;
                attempted_reset = true;
            }
            Err(error) => return Err(error),
        }
    }
}

fn requires_trust_store_reset(error: &Error) -> bool {
    matches!(
        error,
        Error::Verify { rule, .. } if rule == "E_TRUST_STORE_RESET_REQUIRED"
    )
}

fn recover_invalid_trust_store(
    options: &CommonCommandOptions,
    owner_member_id: &str,
    error: Error,
) -> Result<()> {
    recover_invalid_trust_store_with_reader(
        options,
        owner_member_id,
        error,
        std::io::stdin().lock(),
        tty::is_interactive(),
    )
}

fn recover_invalid_trust_store_with_reader<R>(
    options: &CommonCommandOptions,
    owner_member_id: &str,
    error: Error,
    reader: R,
    is_interactive: bool,
) -> Result<()>
where
    R: BufRead,
{
    if !is_interactive {
        return Err(Error::InvalidOperation {
            message: format!(
                "{} (non-interactive mode cannot confirm trust store reset)",
                error.user_message()
            ),
        });
    }

    let base_dir = options.resolve_base_dir()?;
    let path = trust_store_file_path(&base_dir, owner_member_id);
    eprintln!("Warning: {}", error.user_message());
    if !confirm_trust_store_reset_with_reader(&path, reader)? {
        return Err(Error::InvalidOperation {
            message: "Local trust store reset was declined".to_string(),
        });
    }

    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| {
            Error::io_with_source(
                format!(
                    "Failed to remove invalid local trust store {}: {}",
                    display_path_relative_to_cwd(&path),
                    e
                ),
                e,
            )
        })?;
    }
    eprintln!(
        "Deleted local trust store '{}'. Continuing with an empty trust cache.",
        display_path_relative_to_cwd(&path)
    );
    Ok(())
}

fn confirm_trust_store_reset_with_reader<R>(path: &std::path::Path, reader: R) -> Result<bool>
where
    R: BufRead,
{
    prompt_yes_no_with_reader(
        &format!(
            "Delete invalid local trust store '{}' and continue with an empty trust cache?",
            display_path_relative_to_cwd(path)
        ),
        false,
        reader,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/cli_common_trust_recovery_test.rs"]
mod recovery_tests;
