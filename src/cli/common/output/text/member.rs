// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for member commands.

use console::Style;

use crate::cli::common::output::member::{
    view::MemberGithubClaimView, MemberApprovalResultsView, MemberListView, MemberShowView,
    MemberVerificationResultsView,
};
use crate::cli::common::output::trust::review::print_candidate_review;
use crate::support::kid::kid_display_lossy;

const MEMBER_SHOW_LABEL_WIDTH: usize = 12;
const MEMBER_SHOW_BULLET: &str = "\u{25CF}";

pub(crate) fn print_member_sections(view: &MemberListView<'_>) {
    println!("Active:");
    for member in &view.active {
        println!("  {}", member.member_id);
    }

    if !view.incoming.is_empty() {
        println!();
        println!("Incoming:");
        for member in &view.incoming {
            println!("  {}", member.member_id);
        }
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
    let ok = Style::new().green().apply_to("\u{2713}");
    let ng = Style::new().red().apply_to("\u{2717}");
    for result in &view.results {
        if result.verified {
            eprintln!("{} {}: {}", ok, result.member_id, result.message);
        } else {
            eprintln!("{} {}: {}", ng, result.member_id, result.message);
        }
        if let Some(fp) = result.fingerprint {
            eprintln!("  SSH key fingerprint: {}", fp);
        }
    }
    let verified_count = view.results.iter().filter(|result| result.verified).count();
    eprintln!(
        "\nVerified {}/{} members",
        verified_count,
        view.results.len()
    );
}

pub(crate) fn print_member_show(member: &MemberShowView<'_>) {
    for line in build_member_show_lines(member) {
        println!("{line}");
    }
}

pub(crate) fn print_member_add_summary(member_id: &str) {
    eprintln!("Added member '{}' to incoming/", member_id);
}

pub(crate) fn print_member_remove_summary(member_id: &str) {
    eprintln!("Removed member '{}'", member_id);
}

pub(crate) fn print_member_approval_results(view: &MemberApprovalResultsView<'_>) {
    let ok_style = Style::new().green();
    let ng_style = Style::new().red();
    for result in &view.results {
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
        eprintln!("{} {}: {}", status, result.member_id, result.message);
        print_candidate_review(&result.review_candidate);
    }
    let approved_count = view.results.iter().filter(|result| result.approved).count();
    eprintln!(
        "\nApproved {}/{} members",
        approved_count,
        view.results.len()
    );
}

fn build_member_show_lines(member: &MemberShowView<'_>) -> Vec<String> {
    let mut lines = vec![format_member_show_header(member.member_id)];

    push_member_show_section(
        &mut lines,
        "Status".to_string(),
        build_member_show_status_lines(member),
    );
    push_member_show_section(
        &mut lines,
        format_key_section_title(member.kid),
        build_member_show_key_lines(member),
    );
    push_member_show_section(
        &mut lines,
        "SSH Attestation".to_string(),
        vec![format_member_show_row(
            "Fingerprint",
            member.ssh_fingerprint,
        )],
    );
    if let Some(github) = &member.github_claim {
        push_member_show_section(
            &mut lines,
            "GitHub Binding".to_string(),
            build_member_show_binding_lines(github),
        );
    }
    lines
}

fn format_member_show_header(member_id: &str) -> String {
    format!(
        "{} {}",
        MEMBER_SHOW_BULLET,
        Style::new().bold().apply_to(member_id)
    )
}

fn format_key_section_title(kid: &str) -> String {
    let title = format!("Key  {}", kid_display_lossy(kid));
    Style::new().bold().apply_to(title).to_string()
}

fn build_member_show_status_lines(member: &MemberShowView<'_>) -> Vec<String> {
    vec![
        format_member_show_row(
            "Membership",
            &style_membership_value(member.membership_status).to_string(),
        ),
        format_member_show_row(
            "Verification",
            &style_verification_value(member.verification_status).to_string(),
        ),
    ]
}

fn build_member_show_key_lines(member: &MemberShowView<'_>) -> Vec<String> {
    let mut lines = vec![
        format_member_show_row("Algorithm", &member.algorithm),
        format_member_show_row("Expires At", member.expires_at),
    ];
    if let Some(created) = member.created_at {
        lines.push(format_member_show_row("Created At", created));
    }
    lines
}

fn build_member_show_binding_lines(github: &MemberGithubClaimView<'_>) -> Vec<String> {
    vec![format!("  {} (id: {})", github.login, github.id)]
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

fn format_member_show_row(label: &str, value: &str) -> String {
    format!(
        "  {:<width$}: {}",
        label,
        value,
        width = MEMBER_SHOW_LABEL_WIDTH
    )
}

#[cfg(test)]
#[path = "../../../../../tests/unit/cli_common_output_text_member_test.rs"]
mod tests;
