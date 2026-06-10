// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact signature format helpers.
//!
//! Keeps body bytes, signature codecs, algorithm checks, and framed inputs separate.

mod algorithm;
mod body;
mod codec;
mod input;

pub(crate) use algorithm::verify_signature_algorithm;
pub(crate) use body::{
    build_file_artifact_body_bytes, build_kv_artifact_body_bytes,
    build_kv_artifact_body_bytes_from_unsigned, ArtifactBodyBytes,
};
pub(crate) use codec::{decode_ed25519_signature, encode_ed25519_signature};
pub(crate) use input::{build_artifact_signature_input, build_key_possession_mac_message};

#[cfg(test)]
#[path = "../../tests/unit/internal/format_signature_test.rs"]
mod format_signature_test;
