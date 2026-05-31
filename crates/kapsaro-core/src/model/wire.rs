// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0
//! Wire-format constants and domain-separation string literals.
//!
//! Centralizing these reduces typo risk and makes future changes safer. This
//! module intentionally contains only pure constant data used across wire
//! formats and crypto contexts.

/// On-wire `format` identifiers.
pub mod format {
    /// `PublicKey` format identifier.
    pub const PUBLIC_KEY_V1: &str = "kapsaro:format:public-key@1";
    /// `PrivateKey` format identifier.
    pub const PRIVATE_KEY_V1: &str = "kapsaro:format:private-key@1";
    /// Local Trust Store format identifier.
    pub const LOCAL_TRUST_V1: &str = "kapsaro:format:local-trust@1";
    /// FileEncDocument format identifier.
    pub const FILE_ENC_V1: &str = "kapsaro:format:file-enc@1";
    /// `FilePayload` format identifier (used in file-enc payload.protected).
    pub const FILE_PAYLOAD_V1: &str = "kapsaro:format:file-enc:payload@1";
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
    pub const AAD_KV_ENTRY_PAYLOAD_V1: &str = "kapsaro:context:aad:kv-enc:entry-payload@1";

    /// HPKE info discriminator for kv-enc WRAP.
    pub const HPKE_INFO_KV_WRAP_V1: &str = "kapsaro:context:hpke-info:kv-enc:wrap@1";
    /// HPKE info discriminator for file-enc WRAP.
    pub const HPKE_INFO_FILE_WRAP_V1: &str = "kapsaro:context:hpke-info:file-enc:wrap@1";

    /// HKDF info for `PrivateKey` encryption key derivation from SSH signature.
    pub const HKDF_INFO_PRIVATE_KEY_SSHSIG_V1: &str =
        "kapsaro:context:hkdf-info:private-key:sshsig@1";
    /// HKDF info for `PrivateKey` encryption key derivation from password.
    pub const HKDF_INFO_PRIVATE_KEY_PASSWORD_V1: &str =
        "kapsaro:context:hkdf-info:private-key:password@1";
    /// HKDF salt discriminator for file-enc artifact key schedule.
    pub const HKDF_SALT_FILE_V1: &str = "kapsaro:context:hkdf-salt:file-enc@1";
    /// HKDF salt discriminator for kv-enc artifact key schedule.
    pub const HKDF_SALT_KV_V1: &str = "kapsaro:context:hkdf-salt:kv-enc@1";
    /// HKDF info discriminator for file-enc payload content key derivation.
    pub const HKDF_INFO_FILE_CONTENT_KEY_V1: &str =
        "kapsaro:context:hkdf-info:file-enc:content-key@1";
    /// HKDF info discriminator for file-enc key-possession MAC key derivation.
    pub const HKDF_INFO_FILE_MAC_KEY_V1: &str = "kapsaro:context:hkdf-info:file-enc:mac-key@1";
    /// HKDF info discriminator for kv-enc entry CEK derivation.
    pub const HKDF_INFO_KV_CEK_V1: &str = "kapsaro:context:hkdf-info:kv-enc:cek@1";
    /// HKDF info discriminator for kv-enc key-possession MAC key derivation.
    pub const HKDF_INFO_KV_MAC_KEY_V1: &str = "kapsaro:context:hkdf-info:kv-enc:mac-key@1";

    /// MAC domain separator for artifact key-possession proof.
    pub const MAC_DOMAIN_KEY_POSSESSION_V1: &str = "kapsaro:context:mac-domain:key-possession@1";
    /// Signature-input domain separator for signed artifacts.
    pub const SIG_DOMAIN_ARTIFACT_SIGNATURE_V1: &str =
        "kapsaro:context:sig-domain:artifact-signature@1";

    /// Sign message header for SSH `PrivateKey` protection.
    pub const SSHSIG_MESSAGE_PREFIX_PRIVATE_KEY_PROTECTION_V1: &str =
        "kapsaro:context:sshsig-message:private-key:protection@1";
    /// Attestation body discriminator for `PublicKey`.
    pub const SSHSIG_MESSAGE_PUBLIC_KEY_ATTESTATION_V1: &str =
        "kapsaro:context:sshsig-message:public-key:attestation@1";
    /// Message used to check determinism of SSH signing backend.
    pub const SSHSIG_MESSAGE_DETERMINISM_CHECK_V1: &[u8] =
        b"kapsaro:context:sshsig-message:determinism-check@1";

    /// Hash domain separator for recipient set approval records.
    pub const HASH_DOMAIN_RECIPIENT_SET_V1: &str = "kapsaro:context:hash-domain:recipient-set@1";
}

/// PrivateKey protection method identifiers.
pub mod private_key {
    /// Production KDF identifier for PrivateKey encryption.
    pub const PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256: &str = "sshsig-ed25519-hkdf-sha256";
    /// Argon2id-based KDF identifier for portable PrivateKey encryption.
    pub const PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256: &str = "argon2id-m64t3p4-hkdf-sha256";
}
