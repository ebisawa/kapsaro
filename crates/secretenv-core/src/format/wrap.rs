// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Wire-level wrap item validation.
//! Checks shared file-enc and kv-enc wrap structure before domain processing.

use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::model::common::WrapItem;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::wire::algorithm;
use crate::support::limits::validate_wrap_count;
use crate::{Error, Result};
use std::collections::HashSet;

/// Validate wrap items against shared structural constraints.
pub(crate) fn validate_wrap_items(wrap_items: &[WrapItem], context: &str) -> Result<()> {
    validate_wrap_count(wrap_items.len(), context)?;

    let mut seen_recipient_handles = HashSet::new();
    for item in wrap_items {
        validate_unique_recipient_handle(item, context, &mut seen_recipient_handles)?;
        validate_wrap_item(item)?;
    }

    Ok(())
}

fn validate_unique_recipient_handle<'a>(
    item: &'a WrapItem,
    context: &str,
    seen_recipient_handles: &mut HashSet<&'a str>,
) -> Result<()> {
    if seen_recipient_handles.insert(item.recipient_handle.as_str()) {
        return Ok(());
    }

    Err(Error::build_verification_error(
        "E_DUPLICATE_RECIPIENT_HANDLE".to_string(),
        format!(
            "{} contains duplicate rh '{}' in wrap",
            context, item.recipient_handle
        ),
    ))
}

fn validate_wrap_item(item: &WrapItem) -> Result<()> {
    let _ = MemberHandle::try_from(item.recipient_handle.clone())?;
    let _ = Kid::try_from(item.kid.clone())?;
    validate_wrap_algorithm(&item.alg)?;
    let _ = decode_base64url_nopad_array::<32>(&item.enc, "enc")?;
    let _ = decode_base64url_nopad_array::<48>(&item.ct, "ct")?;
    Ok(())
}

fn validate_wrap_algorithm(value: &str) -> Result<()> {
    if value == algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305 {
        return Ok(());
    }

    Err(Error::build_crypto_error(format!(
        "Unsupported HPKE algorithm: {} (expected: {})",
        value,
        algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305
    )))
}
