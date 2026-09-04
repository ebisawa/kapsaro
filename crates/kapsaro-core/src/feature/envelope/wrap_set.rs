// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Parsed recipient wrap set for envelope decryption.
//! Converts wire wrap items into typed crypto inputs after format validation.

use crate::crypto::types::data::{Ciphertext, Enc};
use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::format::wrap::validate_wrap_items;
use crate::model::common::WrapItem;
use crate::model::identity::{Kid, MemberHandle};
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};

/// Parsed recipient wrap with validated domain fields.
#[derive(Debug, Clone)]
pub struct RecipientWrap {
    recipient_handle: MemberHandle,
    kid: Kid,
    enc: Enc,
    ct: Ciphertext,
}

impl RecipientWrap {
    /// Convert one wire wrap item into its typed form.
    ///
    /// The structural checks, the algorithm among them, run once in
    /// `validate_wrap_items` before the set is converted, so this is conversion
    /// only.
    fn parse(item: &WrapItem) -> Result<Self> {
        let recipient_handle = MemberHandle::try_from(item.recipient_handle.clone())?;
        let kid = Kid::try_from(item.kid.clone())?;
        let enc = Enc::from(decode_base64url_nopad_array::<32>(&item.enc, "enc")?.to_vec());
        let ct = Ciphertext::from(decode_base64url_nopad_array::<48>(&item.ct, "ct")?.to_vec());
        Ok(Self {
            recipient_handle,
            kid,
            enc,
            ct,
        })
    }

    pub fn kid(&self) -> &Kid {
        &self.kid
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

    /// Find the entry addressed to this member under this key id.
    ///
    /// Only the recipient handle is unique across a wrap set, so a key id can
    /// appear on more than one entry. Both fields are matched here, so the entry
    /// opened is the one `self_wrap_kid` named rather than another that happens
    /// to carry the same key id. An entry carrying the key id but naming
    /// somebody else is reported rather than opened.
    pub fn find_by_kid_for_member(
        &self,
        kid: &Kid,
        member_handle: &MemberHandle,
    ) -> Result<&RecipientWrap> {
        if let Some(wrap_item) = self
            .items
            .iter()
            .find(|item| &item.kid == kid && &item.recipient_handle == member_handle)
        {
            return Ok(wrap_item);
        }

        match self.items.iter().find(|item| &item.kid == kid) {
            Some(wrap_item) => Err(Error::build_crypto_error(format!(
                "wrap_item.rh '{}' does not match member_handle '{}' for kid '{}'",
                wrap_item.recipient_handle,
                member_handle,
                format_kid_display_lossy(kid.as_str())
            ))),
            None => Err(Error::build_crypto_error(format!(
                "No wrap found for kid '{}' (member: {})",
                format_kid_display_lossy(kid.as_str()),
                member_handle
            ))),
        }
    }

    /// The key id of the entry addressed to this member, if the set holds one.
    ///
    /// `parse` accepted the set only after its recipient handles were checked
    /// for uniqueness, so at most one entry names any given member and the
    /// answer is a single key id rather than a list of candidates.
    pub fn self_wrap_kid(&self, member_handle: &MemberHandle) -> Option<&Kid> {
        self.items
            .iter()
            .find(|item| &item.recipient_handle == member_handle)
            .map(|item| &item.kid)
    }
}
