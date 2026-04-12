// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CEK Derivation for kv-enc

use crate::crypto::kdf;
use crate::crypto::types::data::Ikm;
use crate::crypto::types::keys::{Cek, MasterKey};
use crate::crypto::types::primitives::Salt;
use crate::feature::envelope::binding::build_kv_cek_info;
use crate::support::codec::base64_public::{decode_base64url_nopad_array, encode_base64url_nopad};
use crate::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::debug;
use uuid::Uuid;

/// Derive cek from mk, salt, and sid for kv-enc
///
/// In kv-enc, each entry's cek (Content Encryption Key) is derived from:
/// - mk (Master Key): wrapped in the WRAP line
/// - salt: base64url-encoded 16 bytes random value, used for key derivation
/// - sid: file identifier (UUID) from HEAD line
///
/// cek = HKDF-SHA256(ikm=mk, salt=base64url_decode(salt), info=jcs({p:"secretenv:kv:cek@3", sid}), length=32)
pub fn derive_cek(mk: &MasterKey, salt_b64: &str, sid: &Uuid, debug: bool) -> Result<Cek> {
    if debug {
        debug!("[CRYPTO] HKDF-SHA256: expand");
    }
    let salt_bytes: [u8; 16] = decode_base64url_nopad_array(salt_b64, "salt")?;
    let salt = Salt::new(salt_bytes);
    let ikm = Ikm::from(mk.as_bytes().to_vec());
    let info = build_kv_cek_info(sid)?;
    kdf::expand_to_array(&ikm, Some(&salt), &info)
}

/// Generate a random salt for kv-enc entry encryption
pub(crate) fn generate_salt() -> String {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt_obj = Salt::new(salt_bytes);
    encode_base64url_nopad(salt_obj.as_bytes())
}
