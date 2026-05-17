// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::cli_api::test_support::domain::ssh::SshDeterminismStatus;

#[test]
fn test_ssh_determinism_status_verified() {
    let status = SshDeterminismStatus::Verified;

    assert!(status.is_verified());
    assert_eq!(status.message(), None);
}

#[test]
fn test_ssh_determinism_status_skipped() {
    let status = SshDeterminismStatus::Skipped;

    assert!(!status.is_verified());
    assert_eq!(status.message(), None);
}

#[test]
fn test_ssh_determinism_status_failed_message() {
    let status = SshDeterminismStatus::Failed {
        message: "signature changed".to_string(),
    };

    assert!(!status.is_verified());
    assert_eq!(status.message(), Some("signature changed"));
}
