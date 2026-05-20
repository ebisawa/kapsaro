// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0
//! Wire-format constants and domain-separation string literals.
//!
//! Centralizing these reduces typo risk and makes future changes safer. This
//! module intentionally contains only pure constant data used across wire
//! formats and crypto contexts.

/// On-wire `format` identifiers.
pub mod format {
    /// `PublicKey@6` format identifier.
    pub const PUBLIC_KEY_V6: &str = "secretenv:format:public-key@6";
    /// `PrivateKey@7` format identifier.
    pub const PRIVATE_KEY_V7: &str = "secretenv:format:private-key@7";
    /// Local Trust Store v5 format identifier.
    pub const LOCAL_TRUST_V5: &str = "secretenv:format:local-trust@5";
    /// FileEncDocument@6 format identifier.
    pub const FILE_ENC_V6: &str = "secretenv:format:file-enc@6";
    /// `FilePayload@6` format identifier (used in file-enc payload.protected).
    pub const FILE_PAYLOAD_V6: &str = "secretenv:format:file-enc:payload@6";
}

/// Algorithm identifiers that appear on-wire (e.g. in `payload.aead`, `signature.alg`).
pub mod algorithm {
    /// AEAD identifier used by payload encryption.
    pub const AEAD_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";
    /// Signature algorithm identifier used by Ed25519 signatures.
    pub const SIGNATURE_ED25519: &str = "eddsa-ed25519";
    /// HPKE identifier: X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
    pub const HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305: &str = "hpke-32-1-3";
}

/// JWK/OKP identifiers used in key documents.
pub mod jwk {
    /// OKP curve for KEM.
    pub const CURVE_X25519: &str = "X25519";
    /// OKP curve for signatures.
    pub const CURVE_ED25519: &str = "Ed25519";
}

/// Domain-separation strings for AAD, HPKE info, HKDF info, MAC, SSHSIG messages, and hashes.
pub mod context {
    /// AAD discriminator for KV entry payload encryption.
    pub const AAD_KV_ENTRY_PAYLOAD_V8: &str = "secretenv:context:aad:kv-enc:entry-payload@8";

    /// HPKE info discriminator for kv-enc WRAP.
    pub const HPKE_INFO_KV_WRAP_V8: &str = "secretenv:context:hpke-info:kv-enc:wrap@8";
    /// HPKE info discriminator for file-enc WRAP.
    pub const HPKE_INFO_FILE_WRAP_V6: &str = "secretenv:context:hpke-info:file-enc:wrap@6";

    /// HKDF info for `PrivateKey@7` encryption key derivation from SSH signature.
    pub const HKDF_INFO_PRIVATE_KEY_SSHSIG_V7: &str =
        "secretenv:context:hkdf-info:private-key:sshsig@7";
    /// HKDF info for `PrivateKey@7` encryption key derivation from password.
    pub const HKDF_INFO_PRIVATE_KEY_PASSWORD_V7: &str =
        "secretenv:context:hkdf-info:private-key:password@7";
    /// HKDF info discriminator for kv-enc entry CEK derivation.
    pub const HKDF_INFO_KV_CEK_V8: &str = "secretenv:context:hkdf-info:kv-enc:cek@8";

    /// MAC domain separator for artifact key-possession proof.
    pub const MAC_DOMAIN_KEY_POSSESSION_V1: &str = "secretenv:context:mac-domain:key-possession@1";

    /// Sign message header for SSH `PrivateKey@7` protection.
    pub const SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V7: &str =
        "secretenv:context:sshsig-message:private-key:protection@7";
    /// Message used to check determinism of SSH signing backend.
    pub const SSHSIG_MESSAGE_DETERMINISM_CHECK_V1: &[u8] =
        b"secretenv:context:sshsig-message:determinism-check@1";

    /// Hash domain separator for recipient set approval records.
    pub const HASH_DOMAIN_RECIPIENT_SET_V2: &str = "secretenv:context:hash-domain:recipient-set@2";
}

/// PrivateKey protection method identifiers.
pub mod private_key {
    /// Production KDF identifier for PrivateKey encryption.
    pub const PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256: &str = "sshsig-ed25519-hkdf-sha256";
    /// Argon2id-based KDF identifier for portable PrivateKey encryption.
    pub const PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256: &str = "argon2id-m64t3p4-hkdf-sha256";
}
