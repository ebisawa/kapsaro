// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-facing online verification status.
//! Keeps app and CLI DTOs independent from the online I/O implementation.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OnlineVerificationStatus {
    NotConfigured,
    Verified,
    Failed,
}

impl OnlineVerificationStatus {
    pub fn is_verified(self) -> bool {
        self == Self::Verified
    }
}

impl From<crate::io::verify_online::VerificationStatus> for OnlineVerificationStatus {
    fn from(value: crate::io::verify_online::VerificationStatus) -> Self {
        match value {
            crate::io::verify_online::VerificationStatus::NotConfigured => Self::NotConfigured,
            crate::io::verify_online::VerificationStatus::Verified => Self::Verified,
            crate::io::verify_online::VerificationStatus::Failed => Self::Failed,
        }
    }
}
