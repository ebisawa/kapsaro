// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust Store format canonicalization helpers.

use crate::format::jcs;
use crate::model::trust_store::TrustStoreProtected;
use crate::Result;

/// Build canonical bytes for Trust Store signature computation.
pub fn build_trust_store_signature_bytes(protected: &TrustStoreProtected) -> Result<Vec<u8>> {
    jcs::normalize(protected)
}
