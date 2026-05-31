// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Parsed recipient wrap set for envelope decryption.
//! Converts wire wrap items into typed crypto inputs after format validation.

use crate::crypto::types::data::{Ciphertext, Enc};
use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::format::wrap::validate_wrap_items;
use crate::model::common::WrapItem;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::wire::algorithm;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};

/// Supported HPKE wrap algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapAlgorithm {
    Hpke32_1_3,
}

impl WrapAlgorithm {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305 => Ok(Self::Hpke32_1_3),
            _ => Err(Error::build_crypto_error(format!(
                "Unsupported HPKE algorithm: {} (expected: {})",
                value,
                algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hpke32_1_3 => algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
        }
    }
}

/// Parsed recipient wrap with validated domain fields.
#[derive(Debug, Clone)]
pub struct RecipientWrap {
    recipient_handle: MemberHandle,
    kid: Kid,
    alg: WrapAlgorithm,
    enc: Enc,
    ct: Ciphertext,
}

impl RecipientWrap {
    pub fn parse(item: &WrapItem) -> Result<Self> {
        let recipient_handle = MemberHandle::try_from(item.recipient_handle.clone())?;
        let kid = Kid::try_from(item.kid.clone())?;
        let alg = WrapAlgorithm::parse(&item.alg)?;
        let enc = Enc::from(decode_base64url_nopad_array::<32>(&item.enc, "enc")?.to_vec());
        let ct = Ciphertext::from(decode_base64url_nopad_array::<48>(&item.ct, "ct")?.to_vec());
        Ok(Self {
            recipient_handle,
            kid,
            alg,
            enc,
            ct,
        })
    }

    pub fn recipient_handle(&self) -> &MemberHandle {
        &self.recipient_handle
    }

    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    pub fn alg(&self) -> WrapAlgorithm {
        self.alg
    }

    pub fn enc(&self) -> &Enc {
        &self.enc
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ct
    }
}

/// Parsed set of recipient wraps.
#[derive(Debug, Clone)]
pub struct WrapSet {
    items: Vec<RecipientWrap>,
}

impl WrapSet {
    pub fn parse(wrap_items: &[WrapItem], context: &str) -> Result<Self> {
        validate_wrap_items(wrap_items, context)?;

        let items = wrap_items
            .iter()
            .map(RecipientWrap::parse)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { items })
    }

    pub fn items(&self) -> &[RecipientWrap] {
        &self.items
    }

    pub fn find_by_kid_for_member(&self, kid: &str, member_handle: &str) -> Result<&RecipientWrap> {
        let wrap_item = self
            .items
            .iter()
            .find(|item| item.kid.as_str() == kid)
            .ok_or_else(|| {
                Error::build_crypto_error(format!(
                    "No wrap found for kid '{}' (member: {})",
                    format_kid_display_lossy(kid),
                    member_handle
                ))
            })?;

        if wrap_item.recipient_handle.as_str() != member_handle {
            return Err(Error::build_crypto_error(format!(
                "wrap_item.rh '{}' does not match member_handle '{}' for kid '{}'",
                wrap_item.recipient_handle,
                member_handle,
                format_kid_display_lossy(kid)
            )));
        }

        Ok(wrap_item)
    }

    pub fn self_wrap_kids(&self, member_handle: &str) -> Vec<Kid> {
        let mut kids = Vec::new();
        for item in &self.items {
            if item.recipient_handle.as_str() != member_handle || kids.contains(&item.kid) {
                continue;
            }
            kids.push(item.kid.clone());
        }
        kids
    }
}
