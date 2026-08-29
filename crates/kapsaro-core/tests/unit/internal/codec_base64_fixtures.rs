// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Padded standard base64 encoding for tests that build OpenSSH blobs.
//! kapsaro only ever parses that form, so the encoder belongs with the fixtures.

use crate::format::codec::base64_public::encode_base64_standard_nopad;

/// Standard base64 with padding, as OpenSSH spells its key and signature blobs.
///
/// The padding characters carry no data of their own: they only round the
/// encoding out to a multiple of four, so they are appended to the unpadded
/// encoding the production codec produces.
pub(crate) fn encode_base64_standard(data: &[u8]) -> String {
    let mut encoded = encode_base64_standard_nopad(data);
    while !encoded.len().is_multiple_of(4) {
        encoded.push('=');
    }
    encoded
}
