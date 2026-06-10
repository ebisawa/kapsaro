// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CEK derivation for kv-enc.

use crate::crypto::types::keys::{Cek, MasterKey};
use crate::feature::envelope::key_schedule::KvKeySchedule;
use crate::Result;
use tracing::debug;
use uuid::Uuid;

/// Derive a CEK from MK, sid, key, and entry nonce for kv-enc.
///
/// The entry nonce is the base64url value stored in the entry token.
pub fn derive_cek(
    mk: &MasterKey,
    sid: &Uuid,
    key: &str,
    nonce_b64: &str,
    debug: bool,
) -> Result<Cek> {
    if debug {
        debug!("[CRYPTO] HKDF-SHA256: kv key schedule expand");
    }
    KvKeySchedule::extract(mk, sid)?.derive_cek(key, nonce_b64)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_encrypt_kv_cek_test.rs"]
mod feature_encrypt_kv_cek_test;
