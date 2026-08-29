// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH-related identifiers and constants.

pub const KEY_TYPE_ED25519: &str = "ssh-ed25519";
/// `ssh-keygen -t` argument, used only by the `cli-test-support` harness
/// when it materializes SSH key fixtures.
#[cfg_attr(not(feature = "cli-test-support"), allow(dead_code))]
pub const KEYGEN_TYPE_ED25519: &str = "ed25519";
pub const ATTESTATION_NAMESPACE: &str = "kapsaro-attestation";
pub const KEY_PROTECTION_NAMESPACE: &str = "kapsaro-key-protection";
pub const ATTESTATION_METHOD_SSH_SIGN: &str = "ssh-sign";
