// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for key commands.

use std::path::Path;

use crate::cli::common::output::key::{KeyInfoView, KeyListView};
use secretenv_core::cli_api::presentation::kid::format_kid_display;
use secretenv_core::cli_api::presentation::path::format_path_relative_to_cwd;

const KEY_INFO_LABEL_WIDTH: usize = "Member Handle".len();

pub(crate) fn print_empty_key_list() {
    println!("No members found in keystore");
}

pub(crate) fn print_key_list(result: &KeyListView<'_>, verbose: bool) {
    for entry in &result.entries {
        if entry.keys.is_empty() {
            continue;
        }
        println!("Keys for member: {}", entry.member_handle);
        println!();
        for key_info in &entry.keys {
            print_key_info(key_info, verbose);
        }
    }

    if result.entries.len() > 1 {
        println!(
            "Total: {} member(s), {} key(s)",
            result.entries.len(),
            result.total_keys
        );
    } else {
        println!("Total: {} key(s)", result.total_keys);
    }
}

pub(crate) fn print_key_activate_summary(member_handle: &str, kid: &str) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Activated key for '{}':", member_handle);
    eprintln!("  Kid: {}", kid_display);
}

pub(crate) fn print_key_remove_summary(member_handle: &str, kid: &str, was_active: bool) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Removed key for '{}':", member_handle);
    eprintln!("  Kid: {}", kid_display);
    if was_active {
        eprintln!("  Note: This was the active key. No key is now active.");
    }
}

pub(crate) fn print_generated_key_summary(
    member_handle: &str,
    kid: &str,
    expires_at: &str,
    activated: bool,
) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!();
    if activated {
        eprintln!("Generated and activated key for '{}':", member_handle);
    } else {
        eprintln!("Generated key for '{}':", member_handle);
    }
    eprintln!("  Key ID:  {}", kid_display);
    eprintln!("  Expires: {}", expires_at);
}

pub(crate) fn print_existing_key_summary(member_handle: &str, kid: &str) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!(
        "Using existing key for '{}' ({})",
        member_handle, kid_display
    );
}

pub(crate) fn print_key_export_summary(member_handle: &str, kid: &str, out: &Path) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Exported public key for '{}':", member_handle);
    eprintln!("  Kid:    {}", kid_display);
    eprintln!("  Output: {}", format_path_relative_to_cwd(out));
}

pub(crate) fn print_private_key_export_file_summary(member_handle: &str, kid: &str, out: &Path) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Exported private key for '{}':", member_handle);
    eprintln!("  Kid:    {}", kid_display);
    eprintln!("  Output: {}", format_path_relative_to_cwd(out));
}

pub(crate) fn print_private_key_export_stdout_summary(member_handle: &str, kid: &str) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!();
    eprintln!("Exported private key for '{}':", member_handle);
    eprintln!("  Kid: {}", kid_display);
}

fn print_key_info(key_info: &KeyInfoView<'_>, verbose: bool) {
    let active_marker = if key_info.active { " (ACTIVE)" } else { "" };
    let kid_display = format_kid_display(key_info.kid).unwrap_or_else(|_| key_info.kid.to_string());
    print_key_info_field("Kid", format_args!("{}{}", kid_display, active_marker));
    if verbose {
        print_key_info_field("Format", format_args!("{}", key_info.format));
        print_key_info_field("Member Handle", format_args!("{}", key_info.member_handle));
        print_key_info_field("Created", format_args!("{}", key_info.created_at));
    }
    print_key_info_field("Expires", format_args!("{}", key_info.expires_at));
    println!();
}

fn print_key_info_field(label: &str, value: std::fmt::Arguments<'_>) {
    let padding = KEY_INFO_LABEL_WIDTH.saturating_sub(label.len()) + 1;
    println!("  {label}:{:padding$}{value}", "");
}
