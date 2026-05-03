// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unwrap operations for v3 encryption

use super::wrap::ALG_HPKE_32_1_3;
use crate::crypto::kem::{decode_kem_secret_key, open_base, X25519SecretKey};
use crate::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};
use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::{CryptoContext, DecryptionResult};
use crate::feature::envelope::binding::{build_file_wrap_info, build_kv_wrap_info};
use crate::model::common::WrapItem;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::verified::VerifiedPrivateKey;
use crate::support::codec::base64_public::{
    decode_base64url_nopad, decode_base64url_nopad_ciphertext,
};
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Find a wrap item by key ID in a slice of WrapItems.
///
/// Searches by `kid` (cryptographically bound) rather than `recipient_handle` (informational only).
/// If `recipient_handle` does not match `member_handle`, unwrapping fails with an error.
///
/// # Arguments
/// * `wrap_items` - Slice of WrapItems to search
/// * `kid` - Key ID to find
/// * `member_handle` - Resolved member handle for error messages and recipient_handle-mismatch validation
///
/// # Returns
/// Reference to the matching WrapItem, or an error if not found
pub(crate) fn find_wrap_item_by_kid<'a>(
    wrap_items: &'a [WrapItem],
    kid: &str,
    member_handle: &str,
) -> Result<&'a WrapItem> {
    let wrap_item = wrap_items
        .iter()
        .find(|w| w.kid == kid)
        .ok_or_else(|| Error::Crypto {
            message: format!(
                "No wrap found for kid '{}' (member: {})",
                format_kid_display_lossy(kid),
                member_handle
            ),
            source: None,
        })?;

    // Treat recipient_handle mismatch as a hard failure for defence-in-depth, even though
    // cryptographic binding is still anchored on kid.
    if wrap_item.recipient_handle != member_handle {
        return Err(Error::Crypto {
            message: format!(
                "wrap_item.recipient_handle '{}' does not match member_handle '{}' for kid '{}'",
                wrap_item.recipient_handle,
                member_handle,
                format_kid_display_lossy(kid)
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
    let enc_bytes = decode_base64url_nopad(&wrap_item.enc, "enc")?;
    let enc = Enc::from(enc_bytes);
    let ct = decode_base64url_nopad_ciphertext(&wrap_item.ct, "ct")?;
    Ok((enc, ct))
}

/// Convert HPKE plaintext output to a 32-byte MasterKey.
pub fn parse_master_key_from_plaintext(mk_plaintext: Zeroizing<Plaintext>) -> Result<MasterKey> {
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
            format_kid_display_lossy(&wrap_item.kid)
        );
    }

    let mk_plaintext = open_base(kem_secret_key, &enc, &info, &aad, &ct)?;
    parse_master_key_from_plaintext(mk_plaintext)
}

/// Unwrap master key from file-enc v3 format for a specific member
///
/// This is useful for rewrap operations where you need to get the content key
/// without decrypting the entire payload.
///
/// **Note**: This function selects wrap_item by `kid` (key ID) rather than `recipient_handle` (recipient ID),
/// then validates that the located wrap_item carries the expected `member_handle`.
/// This preserves the cryptographic binding on `kid` (HPKE info includes `kid`) while
/// rejecting inconsistent recipient metadata.
pub fn unwrap_master_key_for_file(
    verified: &VerifiedFileEncDocument,
    member_handle: &str,
    kid: &str,
    private_key: &VerifiedPrivateKey,
    debug: bool,
) -> Result<MasterKey> {
    let secret = verified.document();
    let wrap_item = find_wrap_item_by_kid(&secret.protected.wrap, kid, member_handle)?;

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

pub fn unwrap_master_key_for_file_with_context(
    verified: &VerifiedFileEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<DecryptionResult<MasterKey>> {
    let secret = verified.document();
    let selected_key =
        key_ctx.select_local_decryption_key(&secret.protected.wrap, member_handle, debug)?;
    let wrap_item = find_wrap_item_by_kid(
        &secret.protected.wrap,
        &selected_key.info().kid,
        member_handle,
    )?;
    let kem_sk = decode_kem_secret_key(selected_key.private_key())?;
    let master_key = unwrap_master_key(
        wrap_item,
        &secret.protected.sid,
        &kem_sk,
        build_file_wrap_info,
        debug,
        "unwrap_master_key_for_file_with_context",
    )?;
    Ok(DecryptionResult {
        value: master_key,
        key_info: selected_key.info().clone(),
    })
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
/// * `member_handle` - Resolved member handle for error messages
/// * `kid` - Key ID to find the wrap item
/// * `private_key` - VerifiedPrivateKey containing the KEM private key
/// * `debug` - Enable debug logging
pub fn unwrap_master_key_for_kv(
    sid: &Uuid,
    wrap_items: &[WrapItem],
    member_handle: &str,
    kid: &str,
    private_key: &VerifiedPrivateKey,
    debug: bool,
) -> Result<MasterKey> {
    let wrap_item = find_wrap_item_by_kid(wrap_items, kid, member_handle)?;
    let kem_sk = decode_kem_secret_key(private_key)?;
    unwrap_master_key_from_item(sid, wrap_item, &kem_sk, debug)
}

pub fn unwrap_master_key_for_kv_with_context(
    sid: &Uuid,
    wrap_items: &[WrapItem],
    member_handle: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<DecryptionResult<MasterKey>> {
    let selected_key = key_ctx.select_local_decryption_key(wrap_items, member_handle, debug)?;
    let wrap_item = find_wrap_item_by_kid(wrap_items, &selected_key.info().kid, member_handle)?;
    let kem_sk = decode_kem_secret_key(selected_key.private_key())?;
    let master_key = unwrap_master_key_from_item(sid, wrap_item, &kem_sk, debug)?;
    Ok(DecryptionResult {
        value: master_key,
        key_info: selected_key.info().clone(),
    })
}
