// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact signature algorithm checks.
//!
//! Preserves the existing wire algorithm comparison and error shape.

use crate::crypto::build_crypto_error;
use crate::Result;

pub(crate) fn verify_signature_algorithm(signature_alg: &str, expected_alg: &str) -> Result<()> {
    if signature_alg == expected_alg {
        return Ok(());
    }

    Err(build_crypto_error(
        "Unsupported signature algorithm",
        signature_alg.to_string(),
    ))
}
