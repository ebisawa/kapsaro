// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Interactive presentation and persistence for service read reviews.
//! Keeps prompts and online-verification messaging out of the service layer.

use crate::cli::common::output::text::{print_local_state_diagnostics, print_warning};
use crate::cli::common::output::trust::review::print_trust_review_line;
use crate::cli::common::presentation::tty;
use crate::cli::common::prompt::prompt_yes_no;
use crate::cli::common::trust::{
    build_recipient_rows, format_key_approval_review_lines,
    format_recipient_set_member_review_lines, ArtifactRecipientReviewRow,
};
use kapsaro_core::api::key::format_kid_display_lossy;
use kapsaro_core::api::online::{GitHubOnlineVerifier, VerifiedGitHubEvidence};
use kapsaro_core::api::rewrap::{RewrapAcceptance, RewrapReview, RewrapSession};
use kapsaro_core::api::trust::{
    KnownKeyApprovalEvidence, KnownKeyReviewCandidate, ReadAcceptance, ReadReview, TrustApproval,
    TrustReviewKind, TrustReviewRequest, WorkspaceReadSession,
};
use kapsaro_core::{Error, Result};

pub(crate) fn accept_non_member(review: &mut ReadReview) -> Result<ReadAcceptance> {
    let signer = review
        .non_member_signer()
        .ok_or_else(|| build_target_changed_error("non-member signer review disappeared"))?;
    let recipients = signer
        .recipient_handles()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    review_non_member_with_confirmation(
        signer.candidate(),
        &recipients,
        verify_github_candidate,
        || prompt_yes_no("Accept this signed artifact once?", false),
    )?;
    review.accept_non_member()
}

pub(crate) fn accept_rewrap_non_member(review: &mut RewrapReview) -> Result<RewrapAcceptance> {
    let signer = review
        .non_member_signer()
        .ok_or_else(|| build_target_changed_error("non-member signer review disappeared"))?;
    let recipients = signer
        .recipient_handles()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    review_non_member_with_confirmation(
        signer.candidate(),
        &recipients,
        verify_github_candidate,
        || prompt_yes_no("Accept this signed artifact once?", false),
    )?;
    review.accept_non_member()
}

pub(crate) fn approve_next_rewrap_request(
    session: &RewrapSession<'_>,
    review: &mut RewrapReview,
) -> Result<bool> {
    let Some(request) = review.requests().first() else {
        return Ok(false);
    };
    let approval = review_rewrap_request(review, request)?;
    let outcome = session.apply_review_approval(review, approval)?;
    print_local_state_diagnostics(outcome.warnings());
    Ok(true)
}

fn review_rewrap_request(
    review: &RewrapReview,
    request: &TrustReviewRequest,
) -> Result<TrustApproval> {
    match request.kind() {
        TrustReviewKind::KnownKey => review_rewrap_known_key(review, request),
        TrustReviewKind::RecipientSet | TrustReviewKind::ChangedRecipientSet => {
            review_rewrap_recipient_set(request)
        }
    }
}

fn review_rewrap_known_key(
    review: &RewrapReview,
    request: &TrustReviewRequest,
) -> Result<TrustApproval> {
    let candidate = request.known_key_candidate().ok_or_else(|| {
        build_target_changed_error("rewrap review no longer names a key candidate")
    })?;
    if !tty::is_interactive() {
        return Err(build_non_interactive_key_error(
            candidate,
            review.first_request_is_signer(),
        ));
    }
    let subject = KnownKeyReviewSubject::from_signer_request(review.first_request_is_signer());
    let context = subject.review_context("signer key");
    review_known_key_with_confirmation(candidate, context, subject, verify_github_candidate, || {
        prompt_yes_no("Approve this key?", false)
    })
}

fn review_rewrap_recipient_set(request: &TrustReviewRequest) -> Result<TrustApproval> {
    if !tty::is_interactive() {
        return Err(build_non_interactive_recipient_set_error(request.kind()));
    }
    print_rewrap_recipient_set_review(request);
    let prompt = if request.kind() == TrustReviewKind::ChangedRecipientSet {
        "Update the trusted member set for this secret?"
    } else {
        "Trust this member set for this secret?"
    };
    if !prompt_yes_no(prompt, false)? {
        return Err(build_rejected_error("Recipient set approval was rejected"));
    }
    TrustApproval::recipient_set(
        request
            .sid()
            .ok_or_else(|| build_target_changed_error("recipient set review lost its sid"))?,
        request.recipient_kids().to_vec(),
        request.recipient_handle_hints().to_vec(),
    )
}

fn print_rewrap_recipient_set_review(request: &TrustReviewRequest) {
    for line in format_rewrap_recipient_set_review_lines(request) {
        print_trust_review_line(&line);
    }
}

fn format_rewrap_recipient_set_review_lines(request: &TrustReviewRequest) -> Vec<String> {
    let approved = request.approved_recipient_set().map(build_recipient_rows);
    format_recipient_set_member_review_lines(
        &build_rewrap_recipient_rows(request),
        approved.as_deref(),
    )
}

fn build_rewrap_recipient_rows(request: &TrustReviewRequest) -> Vec<ArtifactRecipientReviewRow> {
    request
        .recipient_kids()
        .iter()
        .map(|kid| {
            let handle = request
                .recipient_handle_hints()
                .iter()
                .find(|hint| hint.kid() == kid)
                .map(|hint| hint.recipient_handle().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            ArtifactRecipientReviewRow::new(handle, kid.to_string())
        })
        .collect()
}

pub(crate) fn approve_next_key(
    session: &WorkspaceReadSession<'_>,
    review: &ReadReview,
    context: &str,
) -> Result<bool> {
    let Some(request) = review.requests().first() else {
        return Ok(false);
    };
    let candidate = request
        .known_key_candidate()
        .ok_or_else(|| build_target_changed_error("read review no longer names a key candidate"))?;
    if !tty::is_interactive() {
        return Err(build_non_interactive_key_error(
            candidate,
            review.first_request_is_signer(),
        ));
    }
    let subject = KnownKeyReviewSubject::from_signer_request(review.first_request_is_signer());
    let context = subject.review_context(context);
    let approval = review_known_key_with_confirmation(
        candidate,
        context,
        subject,
        verify_github_candidate,
        || prompt_yes_no("Approve this key?", false),
    )?;
    let outcome = session.apply_approvals(vec![approval])?;
    print_local_state_diagnostics(outcome.warnings());
    Ok(true)
}

pub(crate) fn print_unresolved_recipients(kids: &[kapsaro_core::api::key::Kid]) {
    for kid in kids {
        print_warning(&format!(
            "Recipient kid is not active.\nKid: {}\nDetails: This may be historical metadata from a stale recipient.\nAction: Run kapsaro rewrap to synchronize current recipients.",
            format_kid_display_lossy(kid)
        ));
    }
}

struct GitHubReview {
    evidence: Option<VerifiedGitHubEvidence>,
    failure: Option<String>,
}

#[derive(Clone, Copy)]
enum KnownKeyReviewSubject {
    Signer,
    Recipient,
}

impl KnownKeyReviewSubject {
    fn from_signer_request(signer_request: bool) -> Self {
        if signer_request {
            Self::Signer
        } else {
            Self::Recipient
        }
    }

    fn review_context(self, signer_context: &str) -> &str {
        match self {
            Self::Signer => signer_context,
            Self::Recipient => "recipient key",
        }
    }

    fn rejection_message(self) -> &'static str {
        match self {
            Self::Signer => "Signer key approval was rejected",
            Self::Recipient => "Recipient key approval was rejected",
        }
    }
}

fn review_known_key_with_confirmation<VerifyOnline, Confirm>(
    candidate: &KnownKeyReviewCandidate,
    context: &str,
    subject: KnownKeyReviewSubject,
    verify_online: VerifyOnline,
    confirm: Confirm,
) -> Result<TrustApproval>
where
    VerifyOnline: FnOnce(&KnownKeyReviewCandidate) -> Result<VerifiedGitHubEvidence>,
    Confirm: FnOnce() -> Result<bool>,
{
    let verification = verify_required_github(candidate, verify_online)?;
    let approval = build_known_key_approval(candidate, &verification)?;
    print_key_review(candidate, context, &verification);
    if !confirm()? {
        return Err(build_rejected_error(subject.rejection_message()));
    }
    Ok(approval)
}

fn review_non_member_with_confirmation<VerifyOnline, Confirm>(
    candidate: &KnownKeyReviewCandidate,
    recipients: &[String],
    verify_online: VerifyOnline,
    confirm: Confirm,
) -> Result<GitHubReview>
where
    VerifyOnline: FnOnce(&KnownKeyReviewCandidate) -> Result<VerifiedGitHubEvidence>,
    Confirm: FnOnce() -> Result<bool>,
{
    let verification = verify_optional_github(candidate, verify_online);
    print_non_member_review(candidate, recipients.iter().cloned(), &verification);
    if !confirm()? {
        return Err(build_rejected_error(
            "Non-member signer acceptance was rejected",
        ));
    }
    Ok(verification)
}

fn verify_required_github<VerifyOnline>(
    candidate: &KnownKeyReviewCandidate,
    verify_online: VerifyOnline,
) -> Result<GitHubReview>
where
    VerifyOnline: FnOnce(&KnownKeyReviewCandidate) -> Result<VerifiedGitHubEvidence>,
{
    if !candidate.has_github_binding() {
        return Ok(GitHubReview {
            evidence: None,
            failure: None,
        });
    }
    verify_online(candidate).map(|evidence| GitHubReview {
        evidence: Some(evidence),
        failure: None,
    })
}

fn verify_optional_github<VerifyOnline>(
    candidate: &KnownKeyReviewCandidate,
    verify_online: VerifyOnline,
) -> GitHubReview
where
    VerifyOnline: FnOnce(&KnownKeyReviewCandidate) -> Result<VerifiedGitHubEvidence>,
{
    if !candidate.has_github_binding() {
        return GitHubReview {
            evidence: None,
            failure: None,
        };
    }
    match verify_online(candidate) {
        Ok(evidence) => GitHubReview {
            evidence: Some(evidence),
            failure: None,
        },
        Err(error) => GitHubReview {
            evidence: None,
            failure: Some(error.format_user_message().to_string()),
        },
    }
}

fn build_known_key_approval(
    candidate: &KnownKeyReviewCandidate,
    verification: &GitHubReview,
) -> Result<TrustApproval> {
    let mut evidence = KnownKeyApprovalEvidence::none()
        .with_ssh_attestor_public_key(candidate.ssh_attestor_public_key());
    if let Some(github) = &verification.evidence {
        evidence = evidence.with_verified_github_account(github.clone());
    }
    TrustApproval::known_key(candidate, evidence)
}

fn verify_github_candidate(candidate: &KnownKeyReviewCandidate) -> Result<VerifiedGitHubEvidence> {
    GitHubOnlineVerifier::new().verify_known_key_candidate(candidate)
}

fn print_non_member_review(
    candidate: &KnownKeyReviewCandidate,
    recipients: impl Iterator<Item = String>,
    verification: &GitHubReview,
) {
    print_trust_review_line("Signer outside active members:");
    print_trust_review_line("");
    print_trust_review_line(
        "This secret was signed by a key that is not in the current active member list.",
    );
    print_trust_review_line("Accept only if you intentionally want to read this artifact once.");
    print_trust_review_line("This decision will not save the signer key as trusted.");
    print_trust_review_line("");
    print_trust_review_line("Signer");
    print_candidate(candidate, verification);
    let recipients = recipients.collect::<Vec<_>>();
    if !recipients.is_empty() {
        print_trust_review_line("");
        print_trust_review_line("Current recipients");
        for recipient in recipients {
            print_trust_review_line(&format!("  - {recipient}"));
        }
    }
}

fn print_key_review(
    candidate: &KnownKeyReviewCandidate,
    context: &str,
    verification: &GitHubReview,
) {
    let intro = format!("This artifact references the {context} below.");
    for line in format_key_approval_review_lines(&intro) {
        print_trust_review_line(&line);
    }
    print_candidate(candidate, verification);
}

fn print_candidate(candidate: &KnownKeyReviewCandidate, verification: &GitHubReview) {
    print_trust_review_line(&format!(
        "  member handle      {}",
        candidate.subject_handle()
    ));
    print_trust_review_line(&format!(
        "  key id             {}",
        format_kid_display_lossy(candidate.kid())
    ));
    print_trust_review_line(&format!(
        "  SSH fingerprint    {}",
        candidate.fingerprint().unwrap_or("unknown")
    ));
    let github = verification
        .evidence
        .as_ref()
        .map(|evidence| {
            format!(
                "{} (id: {}, verified)",
                evidence.account().login(),
                evidence.account().id()
            )
        })
        .unwrap_or_else(|| {
            if candidate.has_github_binding() {
                "not verified".to_string()
            } else {
                "not configured".to_string()
            }
        });
    print_trust_review_line(&format!("  GitHub account     {github}"));
    if let Some(failure) = verification.failure.as_deref() {
        print_warning(&format!(
            "GitHub online verification did not verify this signer: {failure}"
        ));
    }
}

fn build_non_interactive_key_error(
    candidate: &KnownKeyReviewCandidate,
    signer_request: bool,
) -> Error {
    if signer_request {
        return Error::build_verification_error(
            "E_TRUST_UNKNOWN_SIGNER",
            format!(
                "Unknown signer kid '{}' (member: {}) in non-interactive mode",
                candidate.kid(),
                candidate.subject_handle()
            ),
        );
    }
    Error::build_verification_error(
        "E_TRUST_RECIPIENT_UNKNOWN",
        format!(
            "Unknown recipient kid requires approval.\nRecipients: '{}' ({})\nAction: Run kapsaro member verify --approve first.",
            candidate.kid(),
            candidate.subject_handle()
        ),
    )
}

fn build_non_interactive_recipient_set_error(kind: TrustReviewKind) -> Error {
    match kind {
        TrustReviewKind::RecipientSet => Error::build_verification_error(
            "E_RECIPIENT_TRUST_MISSING",
            "This secret's member set has not been reviewed locally.\n\
             Action: Run the command interactively to review it first.",
        ),
        TrustReviewKind::ChangedRecipientSet => Error::build_verification_error(
            "E_RECIPIENT_SET_CHANGED",
            "This secret's member set changed since local review.\n\
             Action: Run the command interactively to review it first.",
        ),
        TrustReviewKind::KnownKey => build_target_changed_error(
            "known-key review cannot be mapped as a recipient-set review",
        ),
    }
}

fn build_rejected_error(message: &str) -> Error {
    Error::build_verification_error("E_TRUST_REJECTED", message)
}

fn build_target_changed_error(message: &str) -> Error {
    Error::build_verification_error("E_TRUST_TARGET_CHANGED", message)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/cli_common_read_review_test.rs"]
mod cli_common_read_review_test;
