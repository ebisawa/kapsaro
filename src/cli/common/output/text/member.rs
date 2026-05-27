// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for member commands.

use console::Style;

use crate::cli::common::output::member::view::{
    MemberApprovalItemView, MemberApprovalResultsView, MemberGithubClaimView, MemberListView,
    MemberShowView, MemberVerificationResultsView,
};
use crate::cli::common::output::text::layout;
use crate::cli::common::output::trust::review::{
    format_candidate_review_lines, print_trust_review_line,
};
use secretenv_core::cli_api::presentation::kid::format_kid_display_lossy;

const MEMBER_SHOW_LABEL_WIDTH: usize = 12;
const MEMBER_SHOW_BULLET: &str = "\u{25CF}";

pub(crate) fn print_member_sections(view: &MemberListView<'_>) {
    for line in format_member_list_lines(view) {
        println!("{line}");
    }
}

fn format_member_list_lines(view: &MemberListView<'_>) -> Vec<String> {
    let mut lines = Vec::new();
    let member_handle_width = member_list_id_width(view);
    push_member_list_section(&mut lines, "Active:", &view.active, member_handle_width);

    if !view.incoming.is_empty() {
        lines.push(String::new());
        push_member_list_section(&mut lines, "Incoming:", &view.incoming, member_handle_width);
    }

    lines
}

fn member_list_id_width(view: &MemberListView<'_>) -> usize {
    view.active
        .iter()
        .chain(view.incoming.iter())
        .map(|member| member.member_handle.len())
        .max()
        .unwrap_or(0)
}

fn push_member_list_section(
    lines: &mut Vec<String>,
    title: &str,
    members: &[crate::cli::common::output::member::view::MemberListEntryView<'_>],
    member_handle_width: usize,
) {
    lines.push(title.to_string());
    for member in members {
        lines.extend(layout::format_pair_row(
            "  ",
            member.member_handle,
            &format_kid_display_lossy(member.kid),
            member_handle_width,
        ));
    }
}

pub(crate) fn print_empty_member_list() {
    println!("No members found in workspace");
}

pub(crate) fn print_empty_member_verification_results() {
    eprintln!("No members found in workspace");
}

pub(crate) fn print_empty_member_approval_results() {
    eprintln!("No members require approval");
}

pub(crate) fn print_member_verification_results(view: &MemberVerificationResultsView<'_>) {
    for line in format_member_verification_results_lines(view) {
        eprintln!("{line}");
    }
}

fn format_member_verification_results_lines(
    view: &MemberVerificationResultsView<'_>,
) -> Vec<String> {
    let ok = Style::new().green().apply_to("\u{2713}");
    let ng = Style::new().red().apply_to("\u{2717}");
    let mut lines = Vec::new();
    for result in &view.results {
        let marker = if result.verified {
            ok.to_string()
        } else {
            ng.to_string()
        };
        lines.extend(layout::format_value_lines(
            "",
            &format!("{} {}: {}", marker, result.member_handle, result.message),
        ));
        if let Some(fp) = result.fingerprint {
            lines.extend(layout::format_value_lines("  SSH key fingerprint: ", fp));
        }
    }
    let verified_count = view.results.iter().filter(|result| result.verified).count();
    lines.push(String::new());
    lines.push(format!(
        "Verified {}/{} members",
        verified_count,
        view.results.len()
    ));
    lines
}

pub(crate) fn print_member_show(member: &MemberShowView<'_>) {
    for line in format_member_show_lines(member) {
        println!("{line}");
    }
}

pub(crate) fn print_member_add_summary(member_handle: &str) {
    eprintln!("Added member '{}' to incoming/", member_handle);
}

pub(crate) fn print_member_remove_summary(member_handle: &str) {
    eprintln!("Removed member '{}'", member_handle);
}

pub(crate) fn print_member_approval_results(view: &MemberApprovalResultsView<'_>) {
    for line in format_member_approval_results_lines(view) {
        if line.starts_with("  ") {
            print_trust_review_line(&line);
        } else {
            eprintln!("{line}");
        }
    }
}

fn format_member_approval_results_lines(view: &MemberApprovalResultsView<'_>) -> Vec<String> {
    let mut lines = Vec::new();
    for result in &view.results {
        lines.extend(format_member_approval_item_lines(result));
        lines.extend(format_candidate_review_lines(&result.review_candidate));
    }
    let approved_count = view.results.iter().filter(|result| result.approved).count();
    lines.push(String::new());
    lines.push(format!(
        "Approved {}/{} members",
        approved_count,
        view.results.len()
    ));
    lines
}

fn format_member_approval_item_lines(result: &MemberApprovalItemView<'_>) -> Vec<String> {
    let ok_style = Style::new().green();
    let ng_style = Style::new().red();
    let status: String = if result.approved {
        if result.verified {
            format!("{}", ok_style.apply_to("\u{2713} approved"))
        } else {
            format!("{}", ok_style.apply_to("\u{2713} approved (manual review)"))
        }
    } else if result.review_required {
        "- skipped".to_string()
    } else {
        format!("{}", ng_style.apply_to("\u{2717} not verified"))
    };
    layout::format_value_lines(
        "",
        &format!("{} {}: {}", status, result.member_handle, result.message),
    )
}

fn format_member_show_lines(member: &MemberShowView<'_>) -> Vec<String> {
    let mut lines = format_member_show_header_lines(member.member_handle);

    push_member_show_section(
        &mut lines,
        "Status".to_string(),
        format_member_show_status_lines(member),
    );
    push_member_show_section(
        &mut lines,
        format_key_section_title(member.kid),
        format_member_show_key_lines(member),
    );
    push_member_show_section(
        &mut lines,
        "SSH Attestation".to_string(),
        format_member_show_row_lines("Fingerprint", member.ssh_fingerprint),
    );
    if let Some(github) = &member.github_claim {
        push_member_show_section(
            &mut lines,
            "GitHub Binding".to_string(),
            format_member_show_binding_lines(github),
        );
    }
    lines
}

fn format_member_show_header(member_handle: &str) -> String {
    format!(
        "{} {}",
        MEMBER_SHOW_BULLET,
        Style::new().bold().apply_to(member_handle)
    )
}

fn format_member_show_header_lines(member_handle: &str) -> Vec<String> {
    vec![format_member_show_header(member_handle)]
}

fn format_key_section_title(kid: &str) -> String {
    let title = format!("Key  {}", format_kid_display_lossy(kid));
    Style::new().bold().apply_to(title).to_string()
}

fn format_member_show_status_lines(member: &MemberShowView<'_>) -> Vec<String> {
    let mut lines = format_member_show_row_lines(
        "Membership",
        &style_membership_value(member.membership_status).to_string(),
    );
    lines.extend(format_member_show_row_lines(
        "Verification",
        &style_verification_value(member.verification_status).to_string(),
    ));
    lines
}

fn format_member_show_key_lines(member: &MemberShowView<'_>) -> Vec<String> {
    let mut lines = format_member_show_row_lines("Algorithm", &member.algorithm);
    lines.extend(format_member_show_row_lines(
        "Expires At",
        member.expires_at,
    ));
    if let Some(created) = member.created_at {
        lines.extend(format_member_show_row_lines("Created At", created));
    }
    lines
}

fn format_member_show_binding_lines(github: &MemberGithubClaimView<'_>) -> Vec<String> {
    layout::format_value_lines("  ", &format!("{} (id: {})", github.login, github.id))
}

fn style_membership_value(value: &str) -> console::StyledObject<String> {
    let style = match value {
        "active" => Style::new().green(),
        _ => Style::new().yellow(),
    };
    style.apply_to(value.to_string())
}

fn style_verification_value(value: &str) -> console::StyledObject<String> {
    let style = match value {
        "valid" => Style::new().green(),
        "expired" => Style::new().yellow(),
        _ => Style::new().red(),
    };
    style.apply_to(value.to_string())
}

fn push_member_show_section(lines: &mut Vec<String>, title: String, body: Vec<String>) {
    lines.push(String::new());
    lines.push(title);
    lines.extend(body);
}

fn format_member_show_row_lines(label: &str, value: &str) -> Vec<String> {
    let prefix = format!("  {:<width$}: ", label, width = MEMBER_SHOW_LABEL_WIDTH);
    layout::format_value_lines(&prefix, value)
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_member_test.rs"]
mod tests;
