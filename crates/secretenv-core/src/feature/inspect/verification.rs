// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature verification display for inspection.

use crate::feature::inspect::{build_section, InspectSection};
use crate::feature::verify::SignatureVerificationReport;
use crate::model::verification::VerifyingKeySource;

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
        if let Some(ref member_handle) = report.signer_handle {
            lines.push(format!("  Signer:      {} (verified)", member_handle));
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
