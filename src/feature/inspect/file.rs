// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File-enc inspection.

use crate::model::file_enc::FileEncDocument;
use crate::support::kid::format_kid_display;

use super::formatter::{
    append_file_payload_info, append_line, append_removed_recipients, append_signer_info,
    append_wrap_item,
};
use super::{build_section, InspectOutput, InspectSection};

fn format_section_lines(build: impl FnOnce(&mut String)) -> Vec<String> {
    let mut out = String::new();
    build(&mut out);
    out.lines().map(ToOwned::to_owned).collect()
}

fn build_file_enc_header_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Header",
        vec![
            format!("  SID:         {}", doc.protected.sid),
            format!("  Created:     {}", doc.protected.created_at),
            format!("  Updated:     {}", doc.protected.updated_at),
        ],
    )
}

fn build_file_enc_payload_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Payload",
        format_section_lines(|out| append_file_payload_info(&doc.protected.payload, out)),
    )
}

fn build_file_enc_wrap_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Wrap Data",
        format_section_lines(|out| {
            append_line(out, format!("  Recipients ({}):", doc.protected.wrap.len()));
            for wrap in &doc.protected.wrap {
                append_line(out, format!("    \u{2022} {}", wrap.recipient_handle));
            }
            append_line(out, "  Wrap Items:");
            for (i, wrap) in doc.protected.wrap.iter().enumerate() {
                append_wrap_item(i, wrap, out);
            }
            append_removed_recipients(doc.protected.removed_recipients.as_ref(), out);
        }),
    )
}

fn build_file_enc_signature_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Signature",
        format_section_lines(|out| {
            let sig = &doc.signature;
            let kid_display = format_kid_display(&sig.kid).unwrap_or_else(|_| sig.kid.clone());
            append_line(out, format!("  Algorithm:   {}", sig.alg));
            append_line(out, format!("  Kid:         {}", kid_display));
            append_signer_info(Some(&sig.signer_pub), out);
            append_line(
                out,
                format!("  Sig:         {}...", &sig.sig[..sig.sig.len().min(40)]),
            );
        }),
    )
}

pub(crate) fn build_file_inspect_output(doc: &FileEncDocument) -> InspectOutput {
    InspectOutput {
        title: "File-Enc v4 Metadata".to_string(),
        sections: vec![
            build_file_enc_header_section(doc),
            build_file_enc_wrap_section(doc),
            build_file_enc_payload_section(doc),
            build_file_enc_signature_section(doc),
        ],
    }
}
