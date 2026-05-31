// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for key commands.

use std::path::Path;

use crate::cli::common::output::key::view::{KeyInfoView, KeyListView};
use crate::cli::common::output::text::layout;
use kapsaro_core::api::online::OnlineVerificationStatus;
use kapsaro_core::cli_api::presentation::kid::format_kid_display;
use kapsaro_core::cli_api::presentation::path::format_path_relative_to_cwd;
use kapsaro_core::cli_api::presentation::ssh::SshDeterminismStatus;
use kapsaro_core::{Error, Result};

const KEY_INFO_LABEL_WIDTH: usize = "Member Handle".len();

pub(crate) fn print_empty_key_list() {
    println!("No members found in keystore");
}

pub(crate) fn print_key_list(result: &KeyListView<'_>, verbose: bool) {
    for line in format_key_list_lines(result, verbose) {
        println!("{line}");
    }
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
    print_stderr_lines(format_key_activate_summary_lines(member_handle, kid));
}

pub(crate) fn print_key_remove_summary(member_handle: &str, kid: &str, was_active: bool) {
    print_stderr_lines(format_key_remove_summary_lines(
        member_handle,
        kid,
        was_active,
    ));
}

fn format_key_activate_summary_lines(member_handle: &str, kid: &str) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Activated key for '{member_handle}':"));
    lines.extend(format_key_summary_field_lines(
        "Kid",
        &display_kid_or_raw(kid),
    ));
    lines
}

fn format_key_remove_summary_lines(
    member_handle: &str,
    kid: &str,
    was_active: bool,
) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Removed key for '{member_handle}':"));
    lines.extend(format_key_summary_field_lines(
        "Kid",
        &display_kid_or_raw(kid),
    ));
    if was_active {
        lines.extend(format_key_summary_field_lines(
            "Note",
            "This was the active key. No key is now active.",
        ));
    }
    lines
}

pub(crate) fn print_generated_key_summary(
    member_handle: &str,
    kid: &str,
    expires_at: &str,
    activated: bool,
) {
    let kid_display = display_kid_or_raw(kid);
    eprintln!();
    if activated {
        print_stderr_lines(format_plain_lines(&format!(
            "Generated and activated key for '{member_handle}':"
        )));
    } else {
        print_stderr_lines(format_plain_lines(&format!(
            "Generated key for '{member_handle}':"
        )));
    }
    print_stderr_lines(format_key_summary_field_lines("Key ID", &kid_display));
    print_stderr_lines(format_key_summary_field_lines("Expires", expires_at));
}

pub(crate) fn print_key_generation_binding_info(
    ssh_fingerprint: &str,
    ssh_determinism: &SshDeterminismStatus,
    github_verification: OnlineVerificationStatus,
) -> Result<()> {
    eprintln!();
    print_stderr_lines(layout::format_value_lines(
        "Using SSH key: ",
        ssh_fingerprint,
    ));
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
    let kid_display = display_kid_or_raw(kid);
    print_stderr_lines(format_plain_lines(&format!(
        "Using existing key for '{member_handle}' ({kid_display})"
    )));
}

pub(crate) fn print_key_export_summary(member_handle: &str, kid: &str, out: &Path) {
    print_stderr_lines(format_key_export_summary_lines(member_handle, kid, out));
}

pub(crate) fn print_private_key_export_file_summary(member_handle: &str, kid: &str, out: &Path) {
    print_stderr_lines(format_private_key_export_file_summary_lines(
        member_handle,
        kid,
        out,
    ));
}

pub(crate) fn print_private_key_export_stdout_summary(member_handle: &str, kid: &str) {
    eprintln!();
    print_stderr_lines(format_private_key_export_stdout_summary_lines(
        member_handle,
        kid,
    ));
}

fn format_key_info_lines(key_info: &KeyInfoView<'_>, verbose: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let active_marker = if key_info.active { " (ACTIVE)" } else { "" };
    let kid_display = display_kid_or_raw(key_info.kid);
    lines.extend(format_key_info_field_lines(
        "Kid",
        &format!("{}{}", kid_display, active_marker),
    ));
    if verbose {
        lines.extend(format_key_info_field_lines("Format", key_info.format));
        lines.extend(format_key_info_field_lines(
            "Member Handle",
            key_info.member_handle,
        ));
        lines.extend(format_key_info_field_lines("Created", key_info.created_at));
    }
    lines.extend(format_key_info_field_lines("Expires", key_info.expires_at));
    lines.push(String::new());
    lines
}

fn format_key_info_field_lines(label: &str, value: &str) -> Vec<String> {
    format_labeled_value_lines(label, value, KEY_INFO_LABEL_WIDTH)
}

fn format_key_export_summary_lines(member_handle: &str, kid: &str, out: &Path) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Exported public key for '{member_handle}':"));
    lines.extend(format_labeled_value_lines(
        "Kid",
        &display_kid_or_raw(kid),
        "Output".len(),
    ));
    lines.extend(format_labeled_value_lines(
        "Output",
        &format_path_relative_to_cwd(out),
        "Output".len(),
    ));
    lines
}

fn format_private_key_export_file_summary_lines(
    member_handle: &str,
    kid: &str,
    out: &Path,
) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Exported private key for '{member_handle}':"));
    lines.extend(format_labeled_value_lines(
        "Kid",
        &display_kid_or_raw(kid),
        "Output".len(),
    ));
    lines.extend(format_labeled_value_lines(
        "Output",
        &format_path_relative_to_cwd(out),
        "Output".len(),
    ));
    lines
}

fn format_private_key_export_stdout_summary_lines(member_handle: &str, kid: &str) -> Vec<String> {
    let mut lines = format_plain_lines(&format!("Exported private key for '{member_handle}':"));
    lines.extend(layout::format_value_lines(
        "  Kid: ",
        &display_kid_or_raw(kid),
    ));
    lines
}

fn format_labeled_value_lines(label: &str, value: &str, label_width: usize) -> Vec<String> {
    let padding = label_width.saturating_sub(label.len()) + 1;
    let prefix = format!("  {label}:{:padding$}", "");
    layout::format_value_lines(&prefix, value)
}

fn format_key_summary_field_lines(label: &str, value: &str) -> Vec<String> {
    let prefix = format!("  {label}: ");
    layout::format_value_lines(&prefix, value)
}

fn format_plain_lines(line: &str) -> Vec<String> {
    layout::format_value_lines("", line)
}

fn print_stderr_lines(lines: Vec<String>) {
    for line in lines {
        eprintln!("{line}");
    }
}

fn display_kid_or_raw(kid: &str) -> String {
    format_kid_display(kid).unwrap_or_else(|_| kid.to_string())
}

fn is_online_verification_verified(status: OnlineVerificationStatus) -> bool {
    matches!(status, OnlineVerificationStatus::Verified)
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_key_test.rs"]
mod tests;
