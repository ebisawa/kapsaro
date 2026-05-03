// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0
//! On-wire identifiers and other shared string literals
//!
//! Centralizing these reduces typo risk and makes future changes safer.
//! This module intentionally contains only pure identifiers/constant data
//! used across the wire formats and crypto contexts.

/// On-wire `format` identifiers.
pub mod format {
    /// `PublicKey@5` format identifier.
    pub const PUBLIC_KEY_V5: &str = "secretenv.public.key@5";
    /// `PrivateKey@6` format identifier.
    pub const PRIVATE_KEY_V6: &str = "secretenv.private.key@6";
    /// Local Trust Store v3 format identifier.
    pub const TRUST_LOCAL_V3: &str = "secretenv.trust.local@3";
    /// FileEncDocument@4 format identifier.
    pub const FILE_ENC_V4: &str = "secretenv.file@4";
    /// `FilePayload@4` format identifier (used in file-enc payload.protected).
    pub const FILE_PAYLOAD_V4: &str = "secretenv.file.payload@4";
}

/// Algorithm identifiers that appear on-wire (e.g. in `payload.aead`, `signature.alg`).
pub mod alg {
    /// AEAD identifier used by v4 payload encryption.
    pub const AEAD_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";
    /// Signature algorithm identifier used by v4 signatures.
    pub const SIGNATURE_ED25519: &str = "eddsa-ed25519";
}

/// JWK/OKP identifiers used in key documents.
pub mod jwk {
    /// OKP curve for KEM.
    pub const CRV_X25519: &str = "X25519";
    /// OKP curve for signatures.
    pub const CRV_ED25519: &str = "Ed25519";
}

/// AAD / HPKE / KDF context identifiers.
pub mod context {
    /// AAD/Context discriminator for KV payload encryption.
    pub const PAYLOAD_KV_V4: &str = "secretenv:kv:payload@4";
    /// AAD/Context discriminator for `PrivateKey@6` encryption.
    pub const PRIVATE_KEY_V6: &str = "secretenv:private-key@6";

    /// HPKE info discriminator for kv-file WRAP.
    pub const HPKE_WRAP_KV_FILE_V4: &str = "secretenv:kv:hpke-wrap@4";
    /// HPKE info discriminator for file WRAP.
    pub const HPKE_WRAP_FILE_V4: &str = "secretenv:file:hpke-wrap@4";

    /// HKDF info prefix for `PrivateKey@6` encryption key derivation from SSH signature.
    pub const SSH_PRIVATE_KEY_ENC_INFO_PREFIX_V6: &str = "secretenv:sshsig-private-key-enc@6";
    /// HKDF info prefix for `PrivateKey@6` encryption key derivation from password.
    pub const PASSWORD_PRIVATE_KEY_ENC_INFO_PREFIX_V6: &str =
        "secretenv:password-private-key-enc@6";
    /// Message used to check determinism of SSH signing backend.
    pub const SSH_DETERMINISM_CHECK_MESSAGE: &[u8] = b"secretenv:determinism-check";

    /// Sign message header for SSH `PrivateKey@6` protection.
    pub const SSH_KEY_PROTECTION_SIGN_MESSAGE_PREFIX_V6: &str = "secretenv:key-protection-ikm@6";
    /// HKDF info prefix for kv-enc entry CEK derivation.
    pub const KV_CEK_INFO_PREFIX_V4: &str = "secretenv:kv:cek@4";
}

/// PrivateKey protection method identifiers.
pub mod private_key {
    /// Production protection method identifier for PrivateKey encryption.
    pub const PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256: &str = "sshsig-ed25519-hkdf-sha256";
    /// Argon2id-based protection method identifier for portable PrivateKey encryption.
    pub const PROTECTION_METHOD_ARGON2ID_M64T3P4_HKDF_SHA256: &str = "argon2id-m64t3p4-hkdf-sha256";
}

/// HPKE algorithm identifiers used in WRAP items.
pub mod hpke {
    /// HPKE algorithm identifier: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
    pub const ALG_HPKE_32_1_3: &str = "hpke-32-1-3";
}
