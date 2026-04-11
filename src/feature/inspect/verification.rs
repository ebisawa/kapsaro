// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature verification display for inspection.

use crate::feature::inspect::{build_section, InspectSection};
use crate::feature::verify::SignatureVerificationReport;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::verification::VerifyingKeySource;

/// Online verification display variants
pub enum OnlineVerificationDisplay {
    /// GitHub verification result available
    GithubResult(VerificationResult),
    /// binding_claims exist but no supported binding is configured
    NoSupportedBinding,
}

/// Build signature verification report section.
pub(crate) fn build_signature_verification_section(
    report: &SignatureVerificationReport,
) -> InspectSection {
    let mut lines = vec![format!(
        "  Status:      {}",
        if report.verified {
            "\u{2714} OK"
        } else {
            "\u{2718} FAILED"
        }
    )];

    if report.verified {
        if let Some(ref member_id) = report.signer_member_id {
            lines.push(format!("  Signer:      {} (verified)", member_id));
        }
        if let Some(ref source) = report.source {
            let source_str = match source {
                VerifyingKeySource::SignerPubEmbedded => "signer_pub embedded",
            };
            lines.push(format!("  Source:      {}", source_str));
        }
        for warning in &report.warnings {
            lines.push(format!("  Warning:     \u{26a0} {}", warning));
        }
    } else {
        lines.push(format!("  Reason:      {}", report.message));
    }
    build_section("Signature Verification", lines)
}

/// Build online verification section.
pub fn build_online_verification_section(
    display: &OnlineVerificationDisplay,
    github_login: Option<&str>,
    github_id: Option<u64>,
) -> InspectSection {
    match display {
        OnlineVerificationDisplay::GithubResult(result) => {
            let mut lines = Vec::new();
            match result.status {
                VerificationStatus::Verified => {
                    lines.push("  Status:      \u{2714} OK".to_string());
                    if let (Some(login), Some(id)) = (github_login, github_id) {
                        lines.push(format!("  Account:     {} (id: {})", login, id));
                    }
                    if let Some(ref fp) = result.fingerprint {
                        lines.push(format!("  SSH key:     {}", fp));
                    }
                    if let Some(key_id) = result.matched_key_id {
                        lines.push(format!("  Matched ID:  {}", key_id));
                    }
                }
                VerificationStatus::Failed | VerificationStatus::NotConfigured => {
                    lines.push("  Status:      \u{2718} FAILED".to_string());
                    lines.push(format!("  Reason:      {}", result.message));
                }
            }
            build_section("Online Verification (GitHub)", lines)
        }
        OnlineVerificationDisplay::NoSupportedBinding => build_section(
            "Online Verification",
            vec!["  Status:      Not available (no supported binding configured)".to_string()],
        ),
    }
}
