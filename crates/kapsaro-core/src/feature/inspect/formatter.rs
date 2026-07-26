// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common formatting functions for inspection.

use crate::model::common::{RemovedRecipient, WrapItem};
use crate::model::file_enc::FilePayload;
use crate::support::display::{push_display_escaped, sanitize_display_field_with_limit};
use crate::support::kid::format_kid_display;

const PAYLOAD_CT_DISPLAY_LEN: usize = 64;
const WRAP_TOKEN_DISPLAY_LEN: usize = 32;
const ATTEST_KEY_DISPLAY_LEN: usize = 60;
pub(crate) const SIGNATURE_DISPLAY_LEN: usize = 40;
pub(crate) const ENTRY_CT_DISPLAY_LEN: usize = 40;

/// Format lines built through the append helpers.
pub(crate) fn format_section_lines(build: impl FnOnce(&mut String)) -> Vec<String> {
    let mut out = String::new();
    build(&mut out);
    out.lines().map(ToOwned::to_owned).collect()
}

/// Shorten a document field for display.
///
/// Inspection runs before signature verification, so every field here is
/// attacker-controlled. Slicing by byte offset would split a multi-byte
/// character, and an embedded newline would forge extra output lines.
pub(crate) fn display_field(value: &str, max_len: usize) -> String {
    sanitize_display_field_with_limit(value, max_len)
}

/// Append file payload information.
pub(crate) fn append_file_payload_info(payload: &FilePayload, out: &mut String) {
    append_line(out, "  Protected:");
    append_line(out, format!("    Format:    {}", payload.protected.format));
    append_line(out, format!("    SID:       {}", payload.protected.sid));
    append_line(
        out,
        format!("    AEAD:      {}", payload.protected.alg.aead),
    );
    append_line(out, "  Encrypted:");
    append_line(out, format!("    Nonce:     {}", payload.encrypted.nonce));
    append_line(
        out,
        format!(
            "    CT:        {} bytes ({})",
            payload.encrypted.ct.len(),
            display_field(&payload.encrypted.ct, PAYLOAD_CT_DISPLAY_LEN)
        ),
    );
}

/// Append wrap item information.
pub(crate) fn append_wrap_item(index: usize, wrap: &WrapItem, out: &mut String) {
    let kid_display = format_kid_display(&wrap.kid).unwrap_or_else(|_| wrap.kid.clone());
    append_line(
        out,
        format!("    [{}] RH:    {}", index, wrap.recipient_handle),
    );
    append_line(out, format!("        Kid:   {}", kid_display));
    append_line(out, format!("        Alg:   {}", wrap.alg));
    append_line(
        out,
        format!(
            "        Enc:   {}",
            display_field(&wrap.enc, WRAP_TOKEN_DISPLAY_LEN)
        ),
    );
    append_line(
        out,
        format!(
            "        CT:    {}",
            display_field(&wrap.ct, WRAP_TOKEN_DISPLAY_LEN)
        ),
    );
}

/// Append removed recipients history.
pub(crate) fn append_removed_recipients(removed: Option<&Vec<RemovedRecipient>>, out: &mut String) {
    if let Some(removed) = removed {
        if !removed.is_empty() {
            append_line(out, "");
            append_line(out, format!("  Removed Recipients ({}):", removed.len()));
            for r in removed {
                let kid_display = format_kid_display(&r.kid).unwrap_or_else(|_| r.kid.clone());
                append_line(
                    out,
                    format!(
                        "    \u{2022} {} (kid: {}, removed at {})",
                        r.recipient_handle, kid_display, r.removed_at
                    ),
                );
            }
        }
    }
}

/// Append signer attestation information for any document type.
pub(crate) fn append_signer_info(
    signer_pub: Option<&crate::model::public_key::PublicKey>,
    out: &mut String,
) {
    if let Some(signer_pub) = signer_pub {
        let attestation = &signer_pub.protected.attestation;
        append_line(
            out,
            format!(
                "  Signer:      {} (claimed)",
                signer_pub.protected.subject_handle
            ),
        );
        append_line(out, format!("  Attestation: {}", attestation.method));
        if attestation.pub_.is_empty() {
            append_line(out, "  Attest Key:  (empty)");
        } else {
            append_line(
                out,
                format!(
                    "  Attest Key:  {}",
                    display_field(&attestation.pub_, ATTEST_KEY_DISPLAY_LEN)
                ),
            );
        }
    } else {
        append_line(out, "  Signer:      (not embedded, search by kid)");
    }
}

/// Append a line to output string.
///
/// Escaping happens here so that no interpolated document field can inject
/// extra lines into a section, whether or not the field is truncated.
pub(crate) fn append_line(out: &mut String, line: impl AsRef<str>) {
    push_display_escaped(out, line.as_ref());
    out.push('\n');
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_inspect_formatter_test.rs"]
mod feature_inspect_formatter_test;
