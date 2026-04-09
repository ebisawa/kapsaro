// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::kv::document::UnsignedKvDocument;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::header::KvHeader;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::Result;

use super::super::builder::KvDocumentBuilder;
use super::super::entry_codec::detect_token_codec;

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

pub(crate) fn sign_unsigned_with_key_context(
    unsigned: UnsignedKvDocument,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<String> {
    let signing = build_signing_context(key_ctx, debug)?;
    super::super::sign::sign_unsigned_kv_document(unsigned, &signing)
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
