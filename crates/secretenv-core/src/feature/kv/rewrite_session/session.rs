// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::kv::decrypt::decrypt_kv_document_with_context;
use crate::feature::kv::document::KvDocumentDraft;
use crate::feature::kv::query::decode_decrypted_kv_values;
use crate::feature::recipient::resolve_verified_recipients;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::enc::canonical::extract_recipients_from_wrap;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::header::KvHeader;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::secret::SecretString;
use crate::Result;
use std::collections::HashMap;

use super::super::entry_codec::detect_token_codec;
use super::encrypt::encrypt_kv_map_with_key_context;
use super::history::{detect_disclosed_entries, merge_removed_history_from_old};
use super::unsigned::{
    build_unsigned_from_verified, sign_unsigned_with_key_context, unwrap_master_key_from_verified,
};

pub(crate) struct VerifiedKvRewriteSession<'a> {
    verified: VerifiedKvEncDocument,
    member_handle: &'a str,
    key_ctx: &'a CryptoContext,
    token_codec: Option<TokenCodec>,
    debug: bool,
}

pub(crate) struct KvRecipientRewriteRequest<'a> {
    pub new_recipients: &'a [String],
    pub removed_recipients: &'a [String],
    pub disclosed: bool,
    pub preserve_removed_history: bool,
}

impl<'a> VerifiedKvRewriteSession<'a> {
    pub(crate) fn load(
        content: &KvEncContent,
        member_handle: &'a str,
        key_ctx: &'a CryptoContext,
        token_codec: Option<TokenCodec>,
        debug: bool,
    ) -> Result<Self> {
        let verified = verify_kv_content(content, debug)?;
        Ok(Self::from_verified(
            verified,
            member_handle,
            key_ctx,
            token_codec,
            debug,
        ))
    }

    pub(crate) fn from_verified(
        verified: VerifiedKvEncDocument,
        member_handle: &'a str,
        key_ctx: &'a CryptoContext,
        token_codec: Option<TokenCodec>,
        debug: bool,
    ) -> Self {
        Self {
            verified,
            member_handle,
            key_ctx,
            token_codec,
            debug,
        }
    }

    pub(crate) fn document(&self) -> &crate::model::kv_enc::document::KvEncDocument {
        self.verified.document()
    }

    pub(crate) fn token_codec(&self) -> TokenCodec {
        let doc = self.document();
        detect_token_codec(doc.lines(), self.token_codec)
    }

    pub(crate) fn current_recipients(&self) -> Vec<String> {
        extract_recipients_from_wrap(self.document().wrap())
    }

    pub(crate) fn disclosed(&self) -> bool {
        detect_disclosed_entries(self.document())
    }

    pub(crate) fn build_unsigned(&self, head: KvHeader) -> Result<KvDocumentDraft> {
        build_unsigned_from_verified(&self.verified, head, self.token_codec, self.debug)
    }

    pub(crate) fn sign(&self, unsigned: KvDocumentDraft, master_key: &MasterKey) -> Result<String> {
        sign_unsigned_with_key_context(unsigned, master_key, self.key_ctx, self.debug)
    }

    pub(crate) fn unwrap_master_key(&self) -> Result<MasterKey> {
        unwrap_master_key_from_verified(
            &self.verified,
            self.member_handle,
            self.key_ctx,
            self.debug,
        )
    }

    pub(crate) fn decrypt_all_values(&self) -> Result<HashMap<String, SecretString>> {
        let kv_map = decrypt_kv_document_with_context(
            &self.verified,
            self.member_handle,
            self.key_ctx,
            self.debug,
        )?
        .value;
        Ok(decode_decrypted_kv_values(kv_map)?.into_iter().collect())
    }

    pub(crate) fn rewrap_kv_with_recipients(
        &self,
        target_members: Option<&[VerifiedRecipientKey]>,
        request: KvRecipientRewriteRequest<'_>,
    ) -> Result<String> {
        let verified_members = resolve_verified_recipients(
            target_members,
            self.key_ctx,
            request.new_recipients,
            self.debug,
        )?;
        let decrypted_content = self.decrypt_all_values()?;
        let old_wrap = self.document().wrap();

        encrypt_kv_map_with_key_context(
            &decrypted_content,
            &verified_members,
            self.key_ctx,
            self.token_codec(),
            request.disclosed,
            |new_wrap| {
                if request.preserve_removed_history {
                    merge_removed_history_from_old(new_wrap, old_wrap, request.removed_recipients)?;
                }
                Ok(())
            },
            self.debug,
        )
    }
}
