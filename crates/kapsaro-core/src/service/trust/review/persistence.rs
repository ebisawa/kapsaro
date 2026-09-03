// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Persistence of reviewed trust approvals.
//! Saves caller-approved known keys under the trust store lock.

use crate::service::trust::approval::{save_known_key_approvals, ApprovedKnownKey};
use crate::Result;

use crate::service::trust::TrustCommandSession;

pub fn save_approved_known_key_documents(
    session: &TrustCommandSession,
    approvals: &[ApprovedKnownKey],
) -> Result<()> {
    save_known_key_approvals(session, approvals).map(|_| ())
}
