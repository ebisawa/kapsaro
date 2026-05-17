// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH-related identifiers and constants.

pub const KEY_TYPE_ED25519: &str = "ssh-ed25519";
pub const SSHSIG_ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
pub const SSHSIG_ARMOR_END: &str = "-----END SSH SIGNATURE-----";
pub const KEYGEN_TYPE_ED25519: &str = "ed25519";
pub const ATTESTATION_NAMESPACE: &str = "secretenv-attestation";
pub const KEY_PROTECTION_NAMESPACE: &str = "secretenv-key-protection";
pub const ATTESTATION_METHOD_SSH_SIGN: &str = "ssh-sign";
