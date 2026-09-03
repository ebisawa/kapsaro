// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for inspect commands.

use console::Style;

use crate::cli::common::output::text::layout;
use crate::cli::common::output::text::layout::LineTarget;
use crate::cli::common::presentation::format_kid_display_lossy;
use kapsaro_core::api::inspect::{
    ArtifactSignatureMetadata, FileEncInspectMetadata, InspectMetadata, KvEncInspectMetadata,
    OnlineVerificationMetadata, SignatureVerificationMetadata, WrapDataMetadata,
};

const PAYLOAD_CT_DISPLAY_LEN: usize = 64;
const WRAP_TOKEN_DISPLAY_LEN: usize = 32;
const ATTEST_KEY_DISPLAY_LEN: usize = 60;
const SIGNATURE_DISPLAY_LEN: usize = 40;
const ENTRY_CT_DISPLAY_LEN: usize = 40;

pub(crate) struct InspectOutput {
    pub(crate) title: String,
    pub(crate) sections: Vec<InspectSection>,
}

pub(crate) struct InspectSection {
    pub(super) title: String,
    pub(super) lines: Vec<String>,
}

pub(crate) fn build_inspect_output(metadata: &InspectMetadata) -> InspectOutput {
    match metadata {
        InspectMetadata::FileEnc(file) => build_file_output(file),
        InspectMetadata::KvEnc(kv) => build_kv_output(kv),
    }
}

fn build_file_output(file: &FileEncInspectMetadata) -> InspectOutput {
    let mut sections = vec![
        section(
            "Header",
            vec![
                field_line("  SID:         ", &file.header.sid),
                field_line("  Created:     ", &file.header.created_at),
                field_line("  Updated:     ", &file.header.updated_at),
            ],
        ),
        section("Wrap Data", build_wrap_lines(&file.wrap_data)),
        section(
            "Payload",
            vec![
                "  Protected:".to_string(),
                field_line("    Format:    ", &file.payload.protected.format),
                field_line("    SID:       ", &file.payload.protected.sid),
                field_line("    AEAD:      ", &file.payload.protected.alg.aead),
                "  Encrypted:".to_string(),
                field_line("    Nonce:     ", &file.payload.encrypted.nonce),
                format!(
                    "    CT:        {} bytes ({})",
                    file.payload.encrypted.ct.len(),
                    display_field(&file.payload.encrypted.ct, PAYLOAD_CT_DISPLAY_LEN)
                ),
            ],
        ),
        section("Signature", build_signature_lines(&file.signature)),
        build_signature_verification_section(&file.signature_verification),
    ];
    if let Some(online) = &file.online_verification {
        sections.push(build_online_verification_section(online));
    }
    InspectOutput {
        title: "File-Enc v7 Metadata".to_string(),
        sections,
    }
}

fn build_kv_output(kv: &KvEncInspectMetadata) -> InspectOutput {
    let mut sections = vec![
        section(
            "Header",
            vec![
                field_line("  SID:         ", &kv.header.sid),
                field_line("  AEAD:        ", &kv.header.alg.aead),
                field_line("  Created:     ", &kv.header.created_at),
                field_line("  Updated:     ", &kv.header.updated_at),
            ],
        ),
        section("Wrap Data", build_wrap_lines(&kv.wrap_data)),
        section(
            format!("Entries ({})", kv.entries.len()),
            kv.entries
                .iter()
                .enumerate()
                .flat_map(|(index, entry)| {
                    let mut lines = vec![
                        field_line(&format!("  [{index}] Key: "), &entry.key),
                        field_line("      Nonce:   ", &entry.nonce),
                        format!(
                            "      CT:      {} bytes ({})",
                            entry.ct.len(),
                            display_field(&entry.ct, ENTRY_CT_DISPLAY_LEN)
                        ),
                    ];
                    if entry.disclosed {
                        lines.push("      ⚠ DISCLOSED — Secret may need rotation".to_string());
                    }
                    lines
                })
                .collect(),
        ),
        section("Signature", build_signature_lines(&kv.signature)),
        section(
            "Summary",
            vec![format!("  Total Entries: {}", kv.summary.total_entries)],
        ),
        build_signature_verification_section(&kv.signature_verification),
    ];
    if let Some(online) = &kv.online_verification {
        sections.push(build_online_verification_section(online));
    }
    InspectOutput {
        title: "KV-Enc Metadata".to_string(),
        sections,
    }
}

fn section(title: impl Into<String>, lines: Vec<String>) -> InspectSection {
    InspectSection {
        title: title.into(),
        lines,
    }
}

fn build_wrap_lines(wrap: &WrapDataMetadata) -> Vec<String> {
    let mut lines = vec![format!("  Recipients ({}):", wrap.recipients.len())];
    lines.extend(
        wrap.recipients
            .iter()
            .map(|recipient| field_line("    • ", recipient)),
    );
    lines.push("  Wrap Items:".to_string());
    for (index, item) in wrap.wrap_items.iter().enumerate() {
        lines.push(field_line(
            &format!("    [{index}] RH:    "),
            &item.recipient_handle,
        ));
        lines.push(format!(
            "        Kid:   {}",
            format_kid_display_lossy(&item.kid)
        ));
        lines.push(field_line("        Alg:   ", &item.alg));
        lines.push(format!(
            "        Enc:   {}",
            display_field(&item.enc, WRAP_TOKEN_DISPLAY_LEN)
        ));
        lines.push(format!(
            "        CT:    {}",
            display_field(&item.ct, WRAP_TOKEN_DISPLAY_LEN)
        ));
    }
    if !wrap.removed_recipients.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "  Removed Recipients ({}):",
            wrap.removed_recipients.len()
        ));
        for removed in &wrap.removed_recipients {
            lines.push(format!(
                "    • {} (kid: {}, removed at {})",
                escape_field(&removed.recipient_handle),
                format_kid_display_lossy(&removed.kid),
                escape_field(&removed.removed_at)
            ));
        }
    }
    lines
}

fn build_signature_lines(signature: &ArtifactSignatureMetadata) -> Vec<String> {
    vec![
        field_line("  Algorithm:   ", &signature.alg),
        format!(
            "  Kid:         {}",
            format_kid_display_lossy(&signature.kid)
        ),
        field_line(
            "  Key Proof:   ",
            format!("{} (present)", signature.mac_algorithm),
        ),
        field_line(
            "  Signer:      ",
            format!("{} (claimed)", signature.signer_handle),
        ),
        field_line("  Attestation: ", &signature.attestation_method),
        field_line(
            "  Attest Key:  ",
            if signature.attestation_public_key.is_empty() {
                "(empty)".to_string()
            } else {
                display_field(&signature.attestation_public_key, ATTEST_KEY_DISPLAY_LEN)
            },
        ),
        format!(
            "  Sig:         {}",
            display_field(&signature.sig, SIGNATURE_DISPLAY_LEN)
        ),
    ]
}

fn build_signature_verification_section(
    verification: &SignatureVerificationMetadata,
) -> InspectSection {
    let mut lines = vec![format!(
        "  Status:      {}",
        if verification.verified {
            "✔ OK"
        } else {
            "✘ FAILED"
        }
    )];
    if verification.verified {
        if let Some(handle) = &verification.signer_handle {
            lines.push(field_line(
                "  Signer:      ",
                format!("{handle} (verified)"),
            ));
        }
        if verification.source.is_some() {
            lines.push("  Source:      signer_pub embedded".to_string());
        }
        lines.extend(
            verification
                .warnings
                .iter()
                .map(|warning| field_line("  Warning:     ⚠ ", warning)),
        );
    } else {
        lines.push(field_line("  Reason:      ", &verification.message));
    }
    section("Signature Verification", lines)
}

fn build_online_verification_section(online: &OnlineVerificationMetadata) -> InspectSection {
    if online.provider.is_none() {
        return section(
            "Online Verification",
            vec!["  Status:      Not available (no supported binding configured)".to_string()],
        );
    }
    let mut lines = if online.status == "verified" {
        vec!["  Status:      ✔ OK".to_string()]
    } else {
        vec![
            "  Status:      ✘ FAILED".to_string(),
            field_line("  Reason:      ", &online.message),
        ]
    };
    if online.status == "verified" {
        if let Some(account) = &online.account {
            lines.push(field_line(
                "  Account:     ",
                format!("{} (id: {})", account.login, account.id),
            ));
        }
        if let Some(fingerprint) = &online.fingerprint {
            lines.push(field_line("  SSH key:     ", fingerprint));
        }
        if let Some(key_id) = online.matched_key_id {
            lines.push(format!("  Matched ID:  {key_id}"));
        }
    }
    section("Online Verification (GitHub)", lines)
}

fn field_line(prefix: &str, value: impl AsRef<str>) -> String {
    format!("{prefix}{}", escape_field(value.as_ref()))
}

fn display_field(value: &str, max_len: usize) -> String {
    let escaped = escape_field(value);
    if escaped.len() <= max_len {
        return escaped;
    }
    let mut end = max_len.saturating_sub('…'.len_utf8());
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &escaped[..end])
}

fn escape_field(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            ch if ch.is_control() => vec!['?'],
            ch => vec![ch],
        })
        .collect()
}

pub(crate) fn print_inspect_banner(input_display: &str) {
    layout::print_lines(
        format_inspect_banner_lines(input_display),
        LineTarget::Stderr,
    );
    eprintln!();
}

pub(crate) fn format_inspect_output(output: &InspectOutput) -> String {
    let title_style = Style::new().bold();
    let section_style = Style::new().bold();

    let mut out = String::new();
    for line in format_styled_value_lines("", &output.title, &title_style) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');
    for (index, section) in output.sections.iter().enumerate() {
        push_inspect_section(&mut out, section, &section_style);
        if index + 1 != output.sections.len() {
            out.push('\n');
        }
    }
    out.push('\n');
    out
}

fn push_inspect_section(out: &mut String, section: &InspectSection, section_style: &Style) {
    for line in format_styled_value_lines("", &section.title, section_style) {
        out.push_str(&line);
        out.push('\n');
    }
    for line in &section.lines {
        for rendered in format_inspect_line_lines(line) {
            out.push_str(&rendered);
            out.push('\n');
        }
    }
}

fn format_inspect_banner_lines(input_display: &str) -> Vec<String> {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    layout::format_value_lines("Inspecting: ", input_display)
        .into_iter()
        .map(|line| colorize_banner_line(&line, &dim, &bold))
        .collect()
}

fn colorize_banner_line(line: &str, dim: &Style, bold: &Style) -> String {
    if let Some(value) = line.strip_prefix("Inspecting: ") {
        return format!("{} {}", dim.apply_to("Inspecting:"), bold.apply_to(value));
    }
    bold.apply_to(line).to_string()
}

fn format_styled_value_lines(prefix: &str, value: &str, style: &Style) -> Vec<String> {
    layout::format_value_lines(prefix, value)
        .into_iter()
        .map(|line| style.apply_to(line).to_string())
        .collect()
}

fn format_inspect_line_lines(line: &str) -> Vec<String> {
    let (prefix, value) = split_inspect_line_prefix(line);
    layout::format_value_lines(prefix, value)
        .into_iter()
        .map(|line| colorize_inspect_line(&line))
        .collect()
}

fn split_inspect_line_prefix(line: &str) -> (&str, &str) {
    let Some(colon_index) = line.find(':') else {
        return split_leading_whitespace(line);
    };

    let value_start = line[colon_index + 1..]
        .find(|ch: char| !ch.is_whitespace())
        .map(|offset| colon_index + 1 + offset)
        .unwrap_or(line.len());
    line.split_at(value_start)
}

fn split_leading_whitespace(line: &str) -> (&str, &str) {
    let value_start = line
        .find(|ch: char| !ch.is_whitespace())
        .unwrap_or(line.len());
    line.split_at(value_start)
}

fn colorize_inspect_line(line: &str) -> String {
    let ok_style = Style::new().green().for_stdout();
    let ng_style = Style::new().red().for_stdout();
    let warning_style = Style::new().yellow().for_stdout();
    let is_disclosed_warning =
        line.contains("\u{26a0} DISCLOSED \u{2014} Secret may need rotation");
    if line.contains("\u{2714} OK") {
        line.replace(
            "\u{2714} OK",
            &format!("{}", ok_style.apply_to("\u{2714} OK")),
        )
    } else if line.contains("\u{2718} FAILED") {
        line.replace(
            "\u{2718} FAILED",
            &format!("{}", ng_style.apply_to("\u{2718} FAILED")),
        )
    } else if line.trim_start().starts_with("Warning:") || is_disclosed_warning {
        warning_style.apply_to(line).to_string()
    } else {
        line.to_string()
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_inspect_test.rs"]
mod tests;
