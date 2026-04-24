// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc inspection.

use crate::format::schema::document::{parse_kv_entry_token, parse_kv_signature_token};
use crate::model::kv_enc::document::{KvEncDocument, KvFileSignature};
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::line::KvEncLine;
use crate::support::kid::format_kid_display;
use crate::Result;

use super::formatter::{
    append_line, append_removed_recipients, append_signer_info, append_wrap_item,
};
use super::{build_section, InspectOutput, InspectSection};

/// Parsed kv-enc inspection data.
struct KvEncInspectionData {
    head_data: Option<(KvHeader, String)>,
    wrap_data: Option<(KvWrap, String)>,
    entries: Vec<(String, KvEntryValue, String)>,
    signature: Option<(KvFileSignature, String)>,
}

fn format_section_lines(build: impl FnOnce(&mut String)) -> Vec<String> {
    let mut out = String::new();
    build(&mut out);
    out.lines().map(ToOwned::to_owned).collect()
}

fn build_kv_enc_header_section(data: &KvEncInspectionData) -> Option<InspectSection> {
    data.head_data.as_ref().map(|(head, _token)| {
        build_section(
            "Header",
            vec![
                format!("  SID:         {}", head.sid),
                format!("  Created:     {}", head.created_at),
                format!("  Updated:     {}", head.updated_at),
            ],
        )
    })
}

fn build_kv_enc_wrap_section(data: &KvEncInspectionData) -> Option<InspectSection> {
    data.wrap_data.as_ref().map(|(wrap, _token)| {
        build_section(
            "Wrap Data",
            format_section_lines(|out| {
                append_line(out, format!("  Recipients ({}):", wrap.wrap.len()));
                for rid in &wrap.wrap {
                    append_line(out, format!("    \u{2022} {}", rid.rid));
                }
                append_line(out, "  Wrap Items:");
                for (i, wrap_item) in wrap.wrap.iter().enumerate() {
                    append_wrap_item(i, wrap_item, out);
                }
                append_removed_recipients(wrap.removed_recipients.as_ref(), out);
            }),
        )
    })
}

fn build_kv_enc_entries_section(data: &KvEncInspectionData) -> InspectSection {
    build_section(
        format!("Entries ({})", data.entries.len()),
        format_section_lines(|out| {
            for (i, (key, entry, _token)) in data.entries.iter().enumerate() {
                append_line(out, format!("  [{}] Key: {}", i, key));
                append_line(out, format!("      AEAD:    {}", entry.aead));
                append_line(out, format!("      Salt:    {}", entry.salt));
                append_line(out, format!("      K:       {}", entry.k));
                append_line(out, format!("      Nonce:   {}", entry.nonce));
                append_line(
                    out,
                    format!(
                        "      CT:      {} bytes ({}...)",
                        entry.ct.len(),
                        &entry.ct[..entry.ct.len().min(40)]
                    ),
                );
                if entry.disclosed {
                    append_line(
                        out,
                        "      \u{26a0} DISCLOSED \u{2014} Secret may need rotation",
                    );
                }
            }
        }),
    )
}

fn build_kv_enc_signature_section(data: &KvEncInspectionData) -> Option<InspectSection> {
    data.signature.as_ref().map(|(signature, _token)| {
        let kid_display =
            format_kid_display(&signature.kid).unwrap_or_else(|_| signature.kid.clone());
        build_section(
            "Signature",
            format_section_lines(|out| {
                append_line(out, format!("  Algorithm:   {}", signature.alg));
                append_line(out, format!("  Kid:         {}", kid_display));
                append_signer_info(Some(&signature.signer_pub), out);
                append_line(
                    out,
                    format!(
                        "  Sig:         {}...",
                        &signature.sig[..signature.sig.len().min(40)]
                    ),
                );
            }),
        )
    })
}

/// Build inspection data from a KvEncDocument (verified or not).
fn kv_enc_document_to_inspection_data(doc: &KvEncDocument) -> Result<KvEncInspectionData> {
    let mut entries = Vec::new();
    for line in doc.lines() {
        if let KvEncLine::KV { key, token } = line {
            let entry = parse_kv_entry_token(token)?;
            entries.push((key.clone(), entry, token.clone()));
        }
    }
    let signature: Option<(KvFileSignature, String)> =
        parse_kv_signature_token(doc.signature_token())
            .ok()
            .map(|s| (s, String::new()));
    Ok(KvEncInspectionData {
        head_data: Some((doc.head().clone(), String::new())),
        wrap_data: Some((doc.wrap().clone(), String::new())),
        entries,
        signature,
    })
}

pub(crate) fn build_kv_inspect_output(doc: &KvEncDocument) -> Result<InspectOutput> {
    let data = kv_enc_document_to_inspection_data(doc)?;
    let mut sections = Vec::new();

    if let Some(section) = build_kv_enc_header_section(&data) {
        sections.push(section);
    }
    if let Some(section) = build_kv_enc_wrap_section(&data) {
        sections.push(section);
    }
    sections.push(build_kv_enc_entries_section(&data));
    if let Some(section) = build_kv_enc_signature_section(&data) {
        sections.push(section);
    }
    sections.push(build_section(
        "Summary",
        vec![format!("  Total Entries: {}", data.entries.len())],
    ));
    Ok(InspectOutput {
        title: "KV-Enc Metadata".to_string(),
        sections,
    })
}
