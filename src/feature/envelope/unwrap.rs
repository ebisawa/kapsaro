// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unwrap operations for v3 encryption

use super::wrap::ALG_HPKE_32_1_3;
use crate::crypto::kem::{decode_kem_secret_key, open_base, X25519SecretKey};
use crate::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};
use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::binding::{build_file_wrap_info, build_kv_wrap_info};
use crate::model::common::WrapItem;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::verified::VerifiedPrivateKey;
use crate::support::base64url::{b64_decode, b64_decode_ciphertext};
use crate::support::kid::kid_display_lossy;
use crate::{Error, Result};
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Find a wrap item by key ID in a slice of WrapItems.
///
/// Searches by `kid` (cryptographically bound) rather than `rid` (informational only).
/// If `rid` does not match `member_id`, unwrapping fails with an error.
///
/// # Arguments
/// * `wrap_items` - Slice of WrapItems to search
/// * `kid` - Key ID to find
/// * `member_id` - Member ID for error messages and rid-mismatch validation
///
/// # Returns
/// Reference to the matching WrapItem, or an error if not found
pub(crate) fn find_wrap_item_by_kid<'a>(
    wrap_items: &'a [WrapItem],
    kid: &str,
    member_id: &str,
) -> Result<&'a WrapItem> {
    let wrap_item = wrap_items
        .iter()
        .find(|w| w.kid == kid)
        .ok_or_else(|| Error::Crypto {
            message: format!(
                "No wrap found for kid '{}' (member: {})",
                kid_display_lossy(kid),
                member_id
            ),
            source: None,
        })?;

    // Treat rid mismatch as a hard failure for defence-in-depth, even though
    // cryptographic binding is still anchored on kid.
    if wrap_item.rid != member_id {
        return Err(Error::Crypto {
            message: format!(
                "wrap_item.rid '{}' does not match member_id '{}' for kid '{}'",
                wrap_item.rid,
                member_id,
                kid_display_lossy(kid)
            ),
            source: None,
        });
    }

    Ok(wrap_item)
}

/// Validate wrap item algorithm and decode enc/ct fields.
pub fn decode_wrap_item_fields(wrap_item: &WrapItem) -> Result<(Enc, Ciphertext)> {
    if wrap_item.alg != ALG_HPKE_32_1_3 {
        return Err(Error::Crypto {
            message: format!(
                "Unsupported HPKE algorithm: {} (expected: {})",
                wrap_item.alg, ALG_HPKE_32_1_3
            ),
            source: None,
        });
    }
    let enc_bytes = b64_decode(&wrap_item.enc, "enc")?;
    let enc = Enc::from(enc_bytes);
    let ct = b64_decode_ciphertext(&wrap_item.ct, "ct")?;
    Ok((enc, ct))
}

/// Convert HPKE plaintext output to a 32-byte MasterKey.
pub fn plaintext_to_master_key(mk_plaintext: Zeroizing<Plaintext>) -> Result<MasterKey> {
    if mk_plaintext.as_bytes().len() != 32 {
        return Err(Error::Crypto {
            message: format!(
                "Invalid master key length: expected 32, got {}",
                mk_plaintext.as_bytes().len()
            ),
            source: None,
        });
    }

    let mut mk_array = Zeroizing::new([0u8; 32]);
    mk_array.as_mut().copy_from_slice(mk_plaintext.as_bytes());
    Ok(MasterKey::from_zeroizing(mk_array))
}

/// Unwrap master key from a wrap item (common logic)
///
/// This function performs the common HPKE unwrapping operation used by both
/// file-enc and kv-enc formats. The info_builder parameter determines the
/// specific HPKE info format (file or kv_file).
///
/// # Arguments
/// * `wrap_item` - WrapItem to unwrap
/// * `sid` - Session ID (UUID)
/// * `kem_secret_key` - X25519 secret key for unwrapping
/// * `info_builder` - Function to build HPKE info
/// * `debug` - Enable debug logging
/// * `caller` - Caller function name for debug logging
///
/// # Returns
/// Unwrapped MasterKey
pub fn unwrap_master_key(
    wrap_item: &WrapItem,
    sid: &Uuid,
    kem_secret_key: &X25519SecretKey,
    info_builder: fn(&Uuid, &str) -> Result<Info>,
    debug: bool,
    caller: &str,
) -> Result<MasterKey> {
    let (enc, ct) = decode_wrap_item_fields(wrap_item)?;

    let info = info_builder(sid, &wrap_item.kid)?;
    let aad = Aad::from(info.as_bytes());

    if debug {
        debug!(
            "[CRYPTO] HPKE: {}: open_base (kid: {})",
            caller,
            kid_display_lossy(&wrap_item.kid)
        );
    }

    let mk_plaintext = open_base(kem_secret_key, &enc, &info, &aad, &ct)?;
    plaintext_to_master_key(mk_plaintext)
}

/// Unwrap master key from file-enc v3 format for a specific member
///
/// This is useful for rewrap operations where you need to get the content key
/// without decrypting the entire payload.
///
/// **Note**: This function selects wrap_item by `kid` (key ID) rather than `rid` (recipient ID),
/// then validates that the located wrap_item carries the expected `member_id`.
/// This preserves the cryptographic binding on `kid` (HPKE info includes `kid`) while
/// rejecting inconsistent recipient metadata.
pub fn unwrap_master_key_for_file(
    verified: &VerifiedFileEncDocument,
    member_id: &str,
    kid: &str,
    private_key: &VerifiedPrivateKey,
    debug: bool,
) -> Result<MasterKey> {
    let secret = verified.document();
    let wrap_item = find_wrap_item_by_kid(&secret.protected.wrap, kid, member_id)?;

    // Decode KEM secret key
    let kem_sk = decode_kem_secret_key(private_key)?;

    unwrap_master_key(
        wrap_item,
        &secret.protected.sid,
        &kem_sk,
        build_file_wrap_info,
        debug,
        "unwrap_master_key_for_file",
    )
}

/// Unwrap master key from a WRAP item for kv-enc format (low-level API).
///
/// # Arguments
/// * `sid` - Session ID (UUID)
/// * `wrap_item` - WrapItem to unwrap
/// * `kem_secret_key` - X25519 secret key for unwrapping
/// * `debug` - Enable debug logging
pub fn unwrap_master_key_from_item(
    sid: &Uuid,
    wrap_item: &WrapItem,
    kem_secret_key: &X25519SecretKey,
    debug: bool,
) -> Result<MasterKey> {
    unwrap_master_key(
        wrap_item,
        sid,
        kem_secret_key,
        build_kv_wrap_info,
        debug,
        "unwrap_master_key_from_item",
    )
}

/// Unwrap master key from kv-enc wrap data (high-level API).
///
/// Handles finding the wrap item by kid and unwrapping the key.
///
/// # Arguments
/// * `sid` - Session ID (UUID)
/// * `wrap_items` - Slice of WrapItems to search
/// * `member_id` - Member ID for error messages
/// * `kid` - Key ID to find the wrap item
/// * `private_key` - VerifiedPrivateKey containing the KEM private key
/// * `debug` - Enable debug logging
pub fn unwrap_master_key_for_kv(
    sid: &Uuid,
    wrap_items: &[WrapItem],
    member_id: &str,
    kid: &str,
    private_key: &VerifiedPrivateKey,
    debug: bool,
) -> Result<MasterKey> {
    let wrap_item = find_wrap_item_by_kid(wrap_items, kid, member_id)?;
    let kem_sk = decode_kem_secret_key(private_key)?;
    unwrap_master_key_from_item(sid, wrap_item, &kem_sk, debug)
}
