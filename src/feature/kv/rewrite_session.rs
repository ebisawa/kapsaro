// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for verified KV rewrites and re-signing.

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::envelope::signature::SigningContext;
use crate::feature::kv::document::UnsignedKvDocument;
use crate::feature::kv::encrypt::{build_kv_encryption, encrypt_kv_entries};
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::enc::canonical::parse_kv_wrap;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;
use std::collections::HashMap;
use uuid::Uuid;

use super::builder::KvDocumentBuilder;
use super::entry_codec::{detect_token_codec, encode_kv_entries_to_tokens};

pub(crate) struct VerifiedKvRewriteSession<'a> {
    verified: VerifiedKvEncDocument,
    member_id: &'a str,
    key_ctx: &'a CryptoContext,
    token_codec: Option<TokenCodec>,
    debug: bool,
}

impl<'a> VerifiedKvRewriteSession<'a> {
    pub(crate) fn load(
        content: &KvEncContent,
        member_id: &'a str,
        key_ctx: &'a CryptoContext,
        token_codec: Option<TokenCodec>,
        debug: bool,
    ) -> Result<Self> {
        let verified = verify_kv_content(content, key_ctx.workspace_path.as_deref(), debug)?;
        Ok(Self::from_verified(
            verified,
            member_id,
            key_ctx,
            token_codec,
            debug,
        ))
    }

    pub(crate) fn from_verified(
        verified: VerifiedKvEncDocument,
        member_id: &'a str,
        key_ctx: &'a CryptoContext,
        token_codec: Option<TokenCodec>,
        debug: bool,
    ) -> Self {
        Self {
            verified,
            member_id,
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
        detect_token_codec(doc.content(), doc.lines(), self.token_codec)
    }

    pub(crate) fn build_unsigned(&self, head: KvHeader) -> Result<UnsignedKvDocument> {
        build_unsigned_from_verified(&self.verified, head, self.token_codec, self.debug)
    }

    pub(crate) fn rebuild_unsigned_from_content(
        &self,
        content: &str,
    ) -> Result<UnsignedKvDocument> {
        rebuild_unsigned_from_content(content, self.token_codec, self.debug)
    }

    pub(crate) fn sign(&self, unsigned: UnsignedKvDocument) -> Result<String> {
        sign_unsigned_with_key_context(unsigned, self.key_ctx, self.debug)
    }

    pub(crate) fn unwrap_master_key(&self) -> Result<MasterKey> {
        unwrap_master_key_from_verified(&self.verified, self.member_id, self.key_ctx, self.debug)
    }
}

pub(crate) fn build_unsigned_from_verified(
    verified: &VerifiedKvEncDocument,
    head: KvHeader,
    override_codec: Option<TokenCodec>,
    debug: bool,
) -> Result<UnsignedKvDocument> {
    let doc = verified.document();
    let token_codec = detect_token_codec(doc.content(), doc.lines(), override_codec);
    KvDocumentBuilder::from_lines(head, None, doc.lines(), token_codec, debug)
        .map(|builder| builder.build())
}

pub(crate) fn rebuild_unsigned_from_content(
    content: &str,
    override_codec: Option<TokenCodec>,
    debug: bool,
) -> Result<UnsignedKvDocument> {
    let (lines, head, wrap) = parse_kv_wrap(content)?;
    let token_codec = detect_token_codec(content, &lines, override_codec);
    KvDocumentBuilder::from_lines(head, Some(wrap), &lines, token_codec, debug)
        .map(|builder| builder.build())
}

pub(crate) fn sign_unsigned_with_key_context(
    unsigned: UnsignedKvDocument,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<String> {
    let signing = build_signing_context(key_ctx, debug)?;
    super::sign::sign_unsigned_kv_document(unsigned, &signing)
}

pub(crate) fn unwrap_master_key_from_verified(
    verified: &VerifiedKvEncDocument,
    member_id: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<MasterKey> {
    let doc = verified.document();
    crate::feature::envelope::unwrap::unwrap_master_key_for_kv(
        &doc.head.sid,
        &doc.wrap.wrap,
        member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        debug,
    )
}

pub(crate) fn encrypt_and_sign_kv_map<F>(
    kv_map: &HashMap<String, String>,
    members: &[VerifiedRecipientKey],
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    disclosed: bool,
    mutate_wrap: F,
) -> Result<String>
where
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
