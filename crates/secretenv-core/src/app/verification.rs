// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::verify_online::VerificationStatus;

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

impl From<VerificationStatus> for OnlineVerificationStatus {
    fn from(value: VerificationStatus) -> Self {
        match value {
            VerificationStatus::NotConfigured => Self::NotConfigured,
            VerificationStatus::Verified => Self::Verified,
            VerificationStatus::Failed => Self::Failed,
        }
    }
}
