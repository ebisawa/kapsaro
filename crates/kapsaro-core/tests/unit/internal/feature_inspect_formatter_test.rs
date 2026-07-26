// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests that inspection output stays structurally intact for hostile fields.
//! Inspection formats a document before its signature is verified.

use super::{append_signer_info, format_section_lines};
use crate::test_utils::keygen_helpers::build_dummy_public_key;

const TEST_KID: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn signer_section_lines(attestation_pub: &str) -> Vec<String> {
    let mut public_key = build_dummy_public_key(TEST_KID);
    public_key.protected.attestation.pub_ = attestation_pub.to_string();

    format_section_lines(|out| append_signer_info(Some(&public_key), out))
}

/// A newline in the attestation key would otherwise forge additional lines
/// that read like genuine signer metadata.
#[test]
fn test_append_signer_info_escapes_newlines_in_the_attestation_key() {
    let baseline = signer_section_lines("ssh-ed25519 AAAA");

    let lines = signer_section_lines("ssh-ed25519 AAAA\n  Signer:      root (claimed)");

    assert_eq!(lines.len(), baseline.len());
    let attest_line = lines.iter().find(|line| line.contains("Attest Key:"));
    assert!(attest_line.is_some_and(|line| line.contains("\\n")));
}

/// Truncation used to slice by byte offset, which panics when the limit falls
/// inside a multi-byte character.
#[test]
fn test_append_signer_info_truncates_multibyte_attestation_key_safely() {
    let attestation_pub = format!("{}{}", "A".repeat(59), '\u{3042}');

    let lines = signer_section_lines(&attestation_pub);

    let attest_line = lines
        .iter()
        .find(|line| line.contains("Attest Key:"))
        .expect("signer section includes the attestation key");
    assert!(attest_line.ends_with('\u{2026}'));
}

#[test]
fn test_append_signer_info_reports_an_empty_attestation_key() {
    let lines = signer_section_lines("");

    assert!(lines
        .iter()
        .any(|line| line.contains("Attest Key:  (empty)")));
}
