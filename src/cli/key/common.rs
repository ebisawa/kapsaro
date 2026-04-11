// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common utilities for key operations.

use crate::app::verification::OnlineVerificationStatus;
use crate::model::ssh::SshDeterminismStatus;
use crate::{Error, Result};

pub(crate) fn print_key_generation_binding_info(
    ssh_fingerprint: &str,
    ssh_determinism: &SshDeterminismStatus,
    github_verification: OnlineVerificationStatus,
) -> Result<()> {
    eprintln!();
    eprintln!("Using SSH key: {}", ssh_fingerprint);
    if ssh_determinism.is_verified() {
        eprintln!("SSH signature determinism: OK");
    } else if let Some(message) = ssh_determinism.message() {
        return Err(Error::Crypto {
            message: message.to_string(),
            source: None,
        });
    }

    if github_verification.is_verified() {
        eprintln!("GitHub verification: OK");
    }

    Ok(())
}
