// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Wrap item creation for v3 encryption

use crate::crypto::kem::{seal_base, X25519PublicKey};
use crate::crypto::types::data::{Aad, Info, Plaintext};
use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::binding::{build_file_wrap_info, build_kv_wrap_info};
use crate::model::common::WrapItem;
use crate::model::identifiers::hpke;
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::codec::base64_public::{decode_base64url_nopad_array, encode_base64url_nopad};
use crate::support::kid::format_kid_display_lossy;
use crate::support::limits::validate_wrap_count;
use crate::Result;
use tracing::debug;
use uuid::Uuid;

/// HPKE algorithm identifier: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
pub(crate) const ALG_HPKE_32_1_3: &str = hpke::ALG_HPKE_32_1_3;

/// Format type for wrap creation
#[derive(Clone, Copy)]
pub enum WrapFormat {
    File,
    Kv,
}

/// Build a WRAP item using HPKE seal_base.
///
/// This is a common helper that performs the HPKE sealing operation
/// and constructs a WrapItem. The info builder function determines
/// the specific HPKE info format (kv_file or file).
///
/// # Arguments
/// * `member` - VerifiedRecipientKey for the recipient (must be verified with self-signature and SSH attestation)
/// * `sid` - Session ID (UUID)
/// * `master_key` - Master key to wrap
/// * `info_builder` - Function to build HPKE info
/// * `debug` - Enable debug logging
/// * `caller` - Caller function name for debug logging
pub fn build_wrap_item(
    member: &VerifiedRecipientKey,
    sid: &Uuid,
    master_key: &MasterKey,
    info_builder: fn(&Uuid, &str) -> Result<Info>,
    debug: bool,
    caller: &str,
) -> Result<WrapItem> {
    let public_key = member.document();
    let info = info_builder(sid, &public_key.protected.kid)?;
    let kem_pk_bytes: [u8; 32] =
        decode_base64url_nopad_array(&public_key.protected.identity.keys.kem.x, "KEM public key")?;
    let kem_pk = X25519PublicKey::from_bytes(kem_pk_bytes);

    if debug {
        debug!(
            "[CRYPTO] HPKE: {}: seal_base (kid: {})",
            caller,
            format_kid_display_lossy(&public_key.protected.kid)
        );
    }

    let master_key_plaintext = Plaintext::from(master_key.as_bytes().to_vec());
    // Reuse the same canonical context bytes for both HPKE info and AAD.
    let aad = Aad::from(info.as_bytes());
    let (enc, ct) = seal_base(&kem_pk, &info, &aad, &master_key_plaintext)?;

    Ok(WrapItem {
        recipient_handle: public_key.protected.subject_handle.clone(),
        kid: public_key.protected.kid.clone(),
        alg: ALG_HPKE_32_1_3.to_string(),
        enc: encode_base64url_nopad(enc.as_bytes()),
        ct: encode_base64url_nopad(ct.as_bytes()),
    })
}

/// Build a WRAP item for file-enc format
///
/// # Arguments
/// * `member` - VerifiedRecipientKey for the recipient
/// * `sid` - Session ID (UUID)
/// * `content_key` - Content key to wrap
/// * `debug` - Enable debug logging
pub fn build_wrap_item_for_file(
    member: &VerifiedRecipientKey,
    sid: &Uuid,
    content_key: &MasterKey,
    debug: bool,
) -> Result<WrapItem> {
    build_wrap_item(
        member,
        sid,
        content_key,
        build_file_wrap_info,
        debug,
        "build_wrap_item_for_file",
    )
}

/// Build a WRAP item for kv-enc format
///
/// # Arguments
/// * `sid` - Session ID (UUID)
/// * `member` - VerifiedRecipientKey for the recipient
/// * `master_key` - Master key to wrap
/// * `debug` - Enable debug logging
pub fn build_wrap_item_for_kv(
    sid: &Uuid,
    member: &VerifiedRecipientKey,
    master_key: &MasterKey,
    debug: bool,
) -> Result<WrapItem> {
    build_wrap_item(
        member,
        sid,
        master_key,
        build_kv_wrap_info,
        debug,
        "build_wrap_item_for_kv",
    )
}

/// Build wrap items for a list of recipients (common for both file-enc and kv-enc).
///
/// This function builds wrap items for all provided members using the specified format.
/// It handles both file-enc and kv-enc formats by delegating to the appropriate
/// wrap item build function.
///
/// # Arguments
/// * `members` - List of VerifiedRecipientKey for recipients (must be verified)
/// * `sid` - Session ID (UUID)
/// * `master_key` - Master key to wrap
/// * `format` - Format type (File or Kv)
/// * `debug` - Enable debug logging
///
/// # Returns
/// Vector of WrapItem structures
pub fn build_wraps_for_recipients(
    members: &[VerifiedRecipientKey],
    sid: &Uuid,
    master_key: &MasterKey,
    format: WrapFormat,
    debug: bool,
) -> Result<Vec<WrapItem>> {
    validate_wrap_count(members.len(), "Recipients set")?;
    members
        .iter()
        .map(|member| match format {
            WrapFormat::File => build_wrap_item_for_file(member, sid, master_key, debug),
            WrapFormat::Kv => build_wrap_item_for_kv(sid, member, master_key, debug),
        })
        .collect()
}
