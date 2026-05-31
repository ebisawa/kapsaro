// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::ensure_determinism;
use crate::model::ssh::SshDeterminismStatus;

#[test]
fn test_ensure_determinism_accepts_verified() {
    assert!(ensure_determinism(&SshDeterminismStatus::Verified).is_ok());
}

#[test]
fn test_ensure_determinism_rejects_skipped() {
    let err = ensure_determinism(&SshDeterminismStatus::Skipped).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("determinism check was not performed"));
}
