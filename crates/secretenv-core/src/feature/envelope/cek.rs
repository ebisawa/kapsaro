// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CEK Derivation for kv-enc

use crate::crypto::kdf;
use crate::crypto::types::data::Ikm;
use crate::crypto::types::keys::{Cek, MasterKey};
use crate::crypto::types::primitives::{FreshKvSalt, KvSalt};
use crate::feature::envelope::binding::build_kv_cek_info;
use crate::support::codec::base64_public::{decode_base64url_nopad_array, encode_base64url_nopad};
use crate::Result;
use tracing::debug;
use uuid::Uuid;

/// Derive cek from mk, salt, sid, and key for kv-enc
///
/// In kv-enc, each entry's cek (Content Encryption Key) is derived from:
/// - mk (Master Key): wrapped in the WRAP line
/// - salt: base64url-encoded 32 bytes random value, used for key derivation
/// - sid: file identifier (UUID) from HEAD line
/// - key: dotenv KEY from the entry line
///
/// cek = HKDF-SHA256(ikm=mk, salt=base64url_decode(salt), info=jcs({p:"secretenv:context:hkdf-info:kv-enc:cek@7", sid, k:key}), length=32)
pub fn derive_cek(
    mk: &MasterKey,
    salt_b64: &str,
    sid: &Uuid,
    key: &str,
    debug: bool,
) -> Result<Cek> {
    let salt_bytes: [u8; 32] = decode_base64url_nopad_array(salt_b64, "salt")?;
    let salt = KvSalt::new(salt_bytes);
    derive_cek_from_salt(mk, &salt, sid, key, debug)
}

pub(crate) fn derive_cek_from_fresh_salt(
    mk: &MasterKey,
    salt: &FreshKvSalt,
    sid: &Uuid,
    key: &str,
    debug: bool,
) -> Result<Cek> {
    derive_cek_from_salt(mk, salt.as_kv_salt(), sid, key, debug)
}

fn derive_cek_from_salt(
    mk: &MasterKey,
    salt: &KvSalt,
    sid: &Uuid,
    key: &str,
    debug: bool,
) -> Result<Cek> {
    if debug {
        debug!("[CRYPTO] HKDF-SHA256: expand");
    }
    let ikm = Ikm::from(mk.as_bytes().to_vec());
    let info = build_kv_cek_info(sid, key)?;
    kdf::expand_to_array(&ikm, Some(salt), &info)
}

/// Generate a random salt for kv-enc entry encryption
pub(crate) fn generate_salt() -> Result<FreshKvSalt> {
    FreshKvSalt::generate()
}

pub(crate) fn encode_salt(salt: &FreshKvSalt) -> String {
    encode_base64url_nopad(salt.as_bytes())
}
