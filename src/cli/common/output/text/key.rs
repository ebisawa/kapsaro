// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for key commands.

use std::path::Path;

use crate::cli::common::output::key::view::{KeyInfoView, KeyListView};
use crate::cli::common::output::text::layout;
use crate::cli::common::output::text::layout::{KidDisplayFallback, LabelAlignment, LineTarget};
use kapsaro_core::api::online::OnlineVerificationStatus;
use kapsaro_core::cli_api::presentation::path::format_path_relative_to_cwd;
use kapsaro_core::cli_api::presentation::ssh::SshDeterminismStatus;
use kapsaro_core::{Error, Result};

const KEY_INFO_LABEL_WIDTH: usize = "Member Handle".len();

pub(crate) fn print_empty_key_list() {
    println!("No members found in keystore");
}

pub(crate) fn print_key_list(result: &KeyListView<'_>, verbose: bool) {
    layout::print_lines(format_key_list_lines(result, verbose), LineTarget::Stdout);
}

fn format_key_list_lines(result: &KeyListView<'_>, verbose: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for entry in &result.entries {
        if entry.keys.is_empty() {
            continue;
        }
        lines.extend(layout::format_value_lines(
            "Keys for member: ",
            entry.member_handle,
        ));
        lines.push(String::new());
        for key_info in &entry.keys {
            lines.extend(format_key_info_lines(key_info, verbose));
        }
    }

    if result.entries.len() > 1 {
        lines.push(format!(
            "Total: {} member(s), {} key(s)",
            result.entries.len(),
            result.total_keys
        ));
    } else {
        lines.push(format!("Total: {} key(s)", result.total_keys));
    }
    lines
}

pub(crate) fn print_key_activate_summary(member_handle: &str, kid: &str) {
    layout::print_lines(
        format_key_activate_summary_lines(member_handle, kid),
        LineTarget::Stderr,
    );
}

pub(crate) fn print_key_remove_summary(member_handle: &str, kid: &str, was_active: bool) {
    layout::print_lines(
        format_key_remove_summary_lines(member_handle, kid, was_active),
        LineTarget::Stderr,
    );
}

fn format_key_activate_summary_lines(member_handle: &str, kid: &str) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Activated key for '{member_handle}':"));
    lines.extend(format_summary_field_lines(
        "Kid",
        &layout::format_kid_display_text(kid, KidDisplayFallback::Raw),
    ));
    lines
}

fn format_key_remove_summary_lines(
    member_handle: &str,
    kid: &str,
    was_active: bool,
) -> Vec<String> {
    let mut lines = format_key_remove_header_lines(member_handle);
    lines.extend(format_key_remove_kid_lines(kid));
    if was_active {
        lines.extend(format_key_remove_active_note_lines());
    }
    lines
}

fn format_key_remove_header_lines(member_handle: &str) -> Vec<String> {
    format_plain_lines(&format!("Removed key for '{member_handle}':"))
}

fn format_key_remove_kid_lines(kid: &str) -> Vec<String> {
    format_summary_field_lines(
        "Kid",
        &layout::format_kid_display_text(kid, KidDisplayFallback::Raw),
    )
}

fn format_key_remove_active_note_lines() -> Vec<String> {
    format_summary_field_lines("Note", "This was the active key. No key is now active.")
}

pub(crate) fn print_generated_key_summary(
    member_handle: &str,
    kid: &str,
    expires_at: &str,
    activated: bool,
) {
    let kid_display = layout::format_kid_display_text(kid, KidDisplayFallback::Raw);
    eprintln!();
    if activated {
        layout::print_lines(
            format_plain_lines(&format!(
                "Generated and activated key for '{member_handle}':"
            )),
            LineTarget::Stderr,
        );
    } else {
        layout::print_lines(
            format_plain_lines(&format!("Generated key for '{member_handle}':")),
            LineTarget::Stderr,
        );
    }
    layout::print_lines(
        format_summary_field_lines("Key ID", &kid_display),
        LineTarget::Stderr,
    );
    layout::print_lines(
        format_summary_field_lines("Expires", expires_at),
        LineTarget::Stderr,
    );
}

pub(crate) fn print_key_generation_binding_info(
    ssh_fingerprint: &str,
    ssh_determinism: &SshDeterminismStatus,
    github_verification: OnlineVerificationStatus,
) -> Result<()> {
    eprintln!();
    layout::print_lines(
        layout::format_value_lines("Using SSH key: ", ssh_fingerprint),
        LineTarget::Stderr,
    );
    if ssh_determinism.is_verified() {
        eprintln!("SSH signature determinism: OK");
    } else if let Some(message) = ssh_determinism.message() {
        return Err(Error::build_crypto_error(message.to_string()));
    }

    if is_online_verification_verified(github_verification) {
        eprintln!("GitHub verification: OK");
    }

    Ok(())
}

pub(crate) fn print_existing_key_summary(member_handle: &str, kid: &str) {
    let kid_display = layout::format_kid_display_text(kid, KidDisplayFallback::Raw);
    layout::print_lines(
        format_plain_lines(&format!(
            "Using existing key for '{member_handle}' ({kid_display})"
        )),
        LineTarget::Stderr,
    );
}

pub(crate) fn print_key_export_summary(member_handle: &str, kid: &str, out: &Path) {
    layout::print_lines(
        format_key_export_summary_lines(member_handle, kid, out),
        LineTarget::Stderr,
    );
}

pub(crate) fn print_private_key_export_file_summary(member_handle: &str, kid: &str, out: &Path) {
    layout::print_lines(
        format_private_key_export_file_summary_lines(member_handle, kid, out),
        LineTarget::Stderr,
    );
}

pub(crate) fn print_private_key_export_stdout_summary(member_handle: &str, kid: &str) {
    eprintln!();
    layout::print_lines(
        format_private_key_export_stdout_summary_lines(member_handle, kid),
        LineTarget::Stderr,
    );
}

fn format_key_info_lines(key_info: &KeyInfoView<'_>, verbose: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let active_marker = if key_info.active { " (ACTIVE)" } else { "" };
    let kid_display = layout::format_kid_display_text(key_info.kid, KidDisplayFallback::Raw);
    lines.extend(format_info_field_lines(
        "Kid",
        &format!("{}{}", kid_display, active_marker),
    ));
    if verbose {
        lines.extend(format_info_field_lines("Format", key_info.format));
        lines.extend(format_info_field_lines(
            "Member Handle",
            key_info.member_handle,
        ));
        lines.extend(format_info_field_lines("Created", key_info.created_at));
    }
    lines.extend(format_info_field_lines("Expires", key_info.expires_at));
    lines.push(String::new());
    lines
}

fn format_info_field_lines(label: &str, value: &str) -> Vec<String> {
    layout::format_labeled_value_lines(
        label,
        value,
        KEY_INFO_LABEL_WIDTH,
        LabelAlignment::ColonAfterLabel,
    )
}

fn format_key_export_summary_lines(member_handle: &str, kid: &str, out: &Path) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Exported public key for '{member_handle}':"));
    lines.extend(format_export_field_lines(
        "Kid",
        &layout::format_kid_display_text(kid, KidDisplayFallback::Raw),
    ));
    lines.extend(format_export_field_lines(
        "Output",
        &format_path_relative_to_cwd(out),
    ));
    lines
}

fn format_private_key_export_file_summary_lines(
    member_handle: &str,
    kid: &str,
    out: &Path,
) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Exported private key for '{member_handle}':"));
    lines.extend(format_export_field_lines(
        "Kid",
        &layout::format_kid_display_text(kid, KidDisplayFallback::Raw),
    ));
    lines.extend(format_export_field_lines(
        "Output",
        &format_path_relative_to_cwd(out),
    ));
    lines
}

fn format_private_key_export_stdout_summary_lines(member_handle: &str, kid: &str) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Exported private key for '{member_handle}':"));
    lines.extend(layout::format_value_lines(
        "  Kid: ",
        &layout::format_kid_display_text(kid, KidDisplayFallback::Raw),
    ));
    lines
}

fn format_export_field_lines(label: &str, value: &str) -> Vec<String> {
    layout::format_labeled_value_lines(
        label,
        value,
        "Output".len(),
        LabelAlignment::ColonAfterLabel,
    )
}

fn format_summary_field_lines(label: &str, value: &str) -> Vec<String> {
    layout::format_labeled_value_lines(label, value, label.len(), LabelAlignment::ColonAfterLabel)
}

fn format_plain_lines(line: &str) -> Vec<String> {
    layout::format_value_lines("", line)
}

fn is_online_verification_verified(status: OnlineVerificationStatus) -> bool {
    matches!(status, OnlineVerificationStatus::Verified)
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_key_test.rs"]
mod tests;
