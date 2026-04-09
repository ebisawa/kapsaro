// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for member commands.

use console::Style;

use crate::cli::common::output::member::{
    MemberApprovalResultsView, MemberListView, MemberShowView, MemberVerificationResultsView,
};
use crate::cli::common::output::trust::review::print_candidate_review;
use crate::support::kid::build_kid_display;

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
    let kid_display = build_kid_display(member.kid).unwrap_or_else(|_| member.kid.to_string());
    println!("Member: {}", member.member_id);
    println!("Membership:   {}", member.membership_status);
    println!("Key ID: {}", kid_display);
    println!("Format: {}", member.format);
    println!("Expires: {}", member.expires_at);
    println!("Status: {}", member.verification_status);
    if let Some(created) = member.created_at {
        println!("Created: {}", created);
    }
    println!();
    println!("KEM Key: {}/{}", member.kem_key_type, member.kem_curve);
    println!(
        "Signature Key: {}/{}",
        member.sig_key_type, member.sig_curve
    );
    println!();
    println!("SSH Attestation:");
    println!("  Method: {}", member.ssh_attestation_method);
    println!("  SSH Pubkey: {}", member.ssh_attestation_pubkey);

    if let Some(github) = &member.github_claim {
        println!();
        println!("GitHub Claim:");
        println!("  GitHub ID: {}", github.id);
        println!("  GitHub username: {}", github.login);
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
        } else if result.already_known {
            "- already known".to_string()
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
