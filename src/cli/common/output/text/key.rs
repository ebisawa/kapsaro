// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for key commands.

use std::path::Path;

use crate::cli::common::output::key::{KeyInfoView, KeyListView};
use crate::support::kid::format_kid_display;
use crate::support::path::format_path_relative_to_cwd;

pub(crate) fn print_empty_key_list() {
    println!("No members found in keystore");
}

pub(crate) fn print_key_list(result: &KeyListView<'_>, verbose: bool) {
    for entry in &result.entries {
        if entry.keys.is_empty() {
            continue;
        }
        println!("Keys for member: {}", entry.member_id);
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

pub(crate) fn print_key_activate_summary(member_id: &str, kid: &str) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Activated key for '{}':", member_id);
    eprintln!("  Kid: {}", kid_display);
}

pub(crate) fn print_key_remove_summary(member_id: &str, kid: &str, was_active: bool) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Removed key for '{}':", member_id);
    eprintln!("  Kid: {}", kid_display);
    if was_active {
        eprintln!("  Note: This was the active key. No key is now active.");
    }
}

pub(crate) fn print_generated_key_summary(
    member_id: &str,
    kid: &str,
    expires_at: &str,
    activated: bool,
) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!();
    if activated {
        eprintln!("Generated and activated key for '{}':", member_id);
    } else {
        eprintln!("Generated key for '{}':", member_id);
    }
    eprintln!("  Key ID:  {}", kid_display);
    eprintln!("  Expires: {}", expires_at);
}

pub(crate) fn print_existing_key_summary(member_id: &str, kid: &str) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Using existing key for '{}' ({})", member_id, kid_display);
}

pub(crate) fn print_key_export_summary(member_id: &str, kid: &str, out: &Path) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Exported public key for '{}':", member_id);
    eprintln!("  Kid:    {}", kid_display);
    eprintln!("  Output: {}", format_path_relative_to_cwd(out));
}

pub(crate) fn print_private_key_export_file_summary(member_id: &str, kid: &str, out: &Path) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!("Exported private key for '{}':", member_id);
    eprintln!("  Kid:    {}", kid_display);
    eprintln!("  Output: {}", format_path_relative_to_cwd(out));
}

pub(crate) fn print_private_key_export_stdout_summary(member_id: &str, kid: &str) {
    let kid_display = format_kid_display(kid).unwrap_or_else(|_| kid.to_string());
    eprintln!();
    eprintln!("Exported private key for '{}':", member_id);
    eprintln!("  Kid: {}", kid_display);
}

fn print_key_info(key_info: &KeyInfoView<'_>, verbose: bool) {
    let active_marker = if key_info.active { " (ACTIVE)" } else { "" };
    let kid_display = format_kid_display(key_info.kid).unwrap_or_else(|_| key_info.kid.to_string());
    println!("  Kid:        {}{}", kid_display, active_marker);
    if verbose {
        println!("  Format:     {}", key_info.format);
        println!("  Member Handle: {}", key_info.member_id);
        println!("  Created:    {}", key_info.created_at);
    }
    println!("  Expires:    {}", key_info.expires_at);
    println!();
}
