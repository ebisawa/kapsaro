// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV encryption operations

use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::entry::encrypt_entry;
use crate::feature::envelope::signature::SigningContext;
use crate::feature::envelope::wrap::{build_wraps_for_recipients, WrapFormat};
use crate::format::token::TokenCodec;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::secret::SecretString;
use crate::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::builder::KvDocumentBuilder;
use super::entry_codec::encode_kv_entries_to_tokens;

pub trait KvValueRef {
    fn as_kv_value(&self) -> &str;
}

impl<T> KvValueRef for T
where
    T: AsRef<str>,
{
    fn as_kv_value(&self) -> &str {
        self.as_ref()
    }
}

impl KvValueRef for SecretString {
    fn as_kv_value(&self) -> &str {
        self.as_str()
    }
}

/// Build KV encryption context: generate master key, create HEAD/WRAP structures
pub(crate) fn build_kv_encryption(
    members: &[VerifiedRecipientKey],
    sid: &Uuid,
    timestamp: &str,
) -> Result<(MasterKey, KvHeader, KvWrap)> {
    // Generate master key
    let mut master_key_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(master_key_bytes.as_mut());
    let master_key = MasterKey::from_zeroizing(master_key_bytes);

    // Create HEAD token
    let head_data = KvHeader {
        sid: *sid,
        created_at: timestamp.to_string(),
        updated_at: timestamp.to_string(),
    };

    // Create WRAP items for all recipients
    let wrap_items = build_wraps_for_recipients(members, sid, &master_key, WrapFormat::Kv, false)?;

    let wrap_data = KvWrap {
        wrap: wrap_items,
        removed_recipients: None,
    };

    Ok((master_key, head_data, wrap_data))
}

/// Encrypt all KV entries
pub(crate) fn encrypt_kv_entries<V>(
    kv_map: &HashMap<String, V>,
    master_key: &MasterKey,
    sid: &Uuid,
    debug: bool,
    disclosed: bool,
) -> Result<Vec<(String, KvEntryValue)>>
where
    V: KvValueRef,
{
    let mut entries: Vec<_> = kv_map
        .iter()
        .map(|(key, value)| {
            encrypt_entry(
                key,
                value.as_kv_value(),
                master_key,
                sid,
                debug,
                "encrypt_kv_entries",
                disclosed,
            )
            .map(|entry| (key.clone(), entry))
        })
        .collect::<Result<Vec<_>>>()?;

    // Sort for deterministic output
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(entries)
}

/// Encrypt KV map to kv-enc v3 format
///
/// # Arguments
/// * `kv_map` - Key-value map to encrypt
/// * `recipients` - List of recipient member_ids
/// * `members` - Verified public keys with attested identity for recipients
/// * `signing` - Signing context (signing_key, signer_kid, signer_pub, debug)
/// * `token_codec` - Token codec to use (JSON/JCS or CBOR)
///
/// # Returns
/// kv-enc v3 format string with SIG line
pub fn encrypt_kv_document<V>(
    kv_map: &HashMap<String, V>,
    members: &[VerifiedRecipientKey],
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
) -> Result<String>
where
    V: KvValueRef,
{
    encrypt_kv_document_with_disclosed(kv_map, members, signing, token_codec, false)
}

/// Encrypt KV map to kv-enc v3 format with disclosed flag control
pub(crate) fn encrypt_kv_document_with_disclosed<V>(
    kv_map: &HashMap<String, V>,
    members: &[VerifiedRecipientKey],
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    disclosed: bool,
) -> Result<String>
where
    V: KvValueRef,
{
    encrypt_and_sign_kv_map(kv_map, members, signing, token_codec, disclosed, |_| Ok(()))
}

pub fn encrypt_and_sign_kv_map<V, F>(
    kv_map: &HashMap<String, V>,
    members: &[VerifiedRecipientKey],
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    disclosed: bool,
    mutate_wrap: F,
) -> Result<String>
where
    V: KvValueRef,
    F: FnOnce(&mut KvWrap) -> Result<()>,
{
    let timestamp = crate::support::time::current_timestamp()?;
    let sid = Uuid::new_v4();
    let (master_key, head_data, mut wrap_data) = build_kv_encryption(members, &sid, &timestamp)?;
    mutate_wrap(&mut wrap_data)?;

    let entries = encrypt_kv_entries(kv_map, &master_key, &sid, signing.debug, disclosed)?;
    let encoded = encode_kv_entries_to_tokens(
        &entries,
        token_codec,
        signing.debug,
        "encrypt_and_sign_kv_map",
    )?;

    let unsigned = KvDocumentBuilder::new(head_data, wrap_data, token_codec, signing.debug)
        .with_entries(encoded)
        .build();
    super::sign::sign_unsigned_kv_document(unsigned, signing)
}
