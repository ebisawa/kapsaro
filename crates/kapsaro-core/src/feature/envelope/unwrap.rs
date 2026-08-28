// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unwrap operations for v3 encryption

use crate::crypto::kem::{open_base, X25519SecretKey};
use crate::crypto::types::data::{Aad, Info, Plaintext};
use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::{decode_kem_secret_key, CryptoContext, DecryptionResult};
use crate::feature::envelope::binding::{build_file_wrap_info, build_kv_wrap_info};
use crate::feature::envelope::wrap_set::{RecipientWrap, WrapSet};
use crate::model::common::WrapItem;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::support::kid::format_kid_half_display_lossy;
use crate::{Error, Result};
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Convert HPKE plaintext output to a 32-byte MasterKey.
pub fn parse_master_key_from_plaintext(mk_plaintext: Zeroizing<Plaintext>) -> Result<MasterKey> {
    if mk_plaintext.as_bytes().len() != 32 {
        return Err(Error::build_crypto_error(format!(
            "Invalid master key length: expected 32, got {}",
            mk_plaintext.as_bytes().len()
        )));
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
/// * `caller` - Caller function name for debug logging
///
/// # Returns
/// Unwrapped MasterKey
pub fn unwrap_master_key(
    wrap_item: &RecipientWrap,
    sid: &Uuid,
    kem_secret_key: &X25519SecretKey,
    info_builder: fn(&Uuid, &str) -> Result<Info>,
    caller: &str,
) -> Result<MasterKey> {
    let info = info_builder(sid, wrap_item.kid().as_str())?;
    let aad = Aad::from(info.as_bytes());

    debug!(
        "[CRYPTO] HPKE: {}: open_base (kid: {})",
        caller,
        format_kid_half_display_lossy(wrap_item.kid().as_str())
    );

    let mk_plaintext = open_base(
        kem_secret_key,
        wrap_item.enc(),
        &info,
        &aad,
        wrap_item.ciphertext(),
    )?;
    parse_master_key_from_plaintext(mk_plaintext)
}

/// Unwrap the master key of a file-enc document with the local key the context selects.
///
/// The wrap item is located by `kid` rather than by the recipient handle label, then the
/// located item is required to carry the expected `member_handle`. This keeps the
/// cryptographic binding on `kid` (the HPKE info includes it) while rejecting a wrap set
/// whose recipient metadata disagrees with the key that was selected.
pub fn unwrap_master_key_for_file_with_context(
    verified: &VerifiedFileEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
) -> Result<DecryptionResult<MasterKey>> {
    let secret = verified.document();
    let wrap_set = WrapSet::parse(&secret.protected.wrap, "Document")?;
    let selected_key = key_ctx.select_local_decryption_key(&wrap_set, member_handle)?;
    let wrap_item = wrap_set.find_by_kid_for_member(&selected_key.info().kid, member_handle)?;
    let kem_sk = decode_kem_secret_key(selected_key.private_key())?;
    let master_key = unwrap_master_key(
        wrap_item,
        &secret.protected.sid,
        &kem_sk,
        build_file_wrap_info,
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
pub fn unwrap_master_key_from_item(
    sid: &Uuid,
    wrap_item: &RecipientWrap,
    kem_secret_key: &X25519SecretKey,
) -> Result<MasterKey> {
    unwrap_master_key(
        wrap_item,
        sid,
        kem_secret_key,
        build_kv_wrap_info,
        "unwrap_master_key_from_item",
    )
}

/// Unwrap the master key of a kv-enc document with the local key the context selects.
///
/// Like the file-enc path, the wrap item is located by `kid` and the located item is then
/// required to carry the expected `member_handle`.
pub fn unwrap_master_key_for_kv_with_context(
    sid: &Uuid,
    wrap_items: &[WrapItem],
    member_handle: &str,
    key_ctx: &CryptoContext,
) -> Result<DecryptionResult<MasterKey>> {
    let wrap_set = WrapSet::parse(wrap_items, "Document")?;
    let selected_key = key_ctx.select_local_decryption_key(&wrap_set, member_handle)?;
    let wrap_item = wrap_set.find_by_kid_for_member(&selected_key.info().kid, member_handle)?;
    let kem_sk = decode_kem_secret_key(selected_key.private_key())?;
    let master_key = unwrap_master_key_from_item(sid, wrap_item, &kem_sk)?;
    Ok(DecryptionResult {
        value: master_key,
        key_info: selected_key.info().clone(),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_decrypt_unwrap_test.rs"]
mod feature_decrypt_unwrap_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_decrypt_unwrap_validation_test.rs"]
mod feature_decrypt_unwrap_validation_test;
