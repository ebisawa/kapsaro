// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::build_signing_context;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::key_possession::verify_kv_key_possession;
use crate::feature::envelope::unwrap::unwrap_master_key_for_kv_with_context;
use crate::format::kv::document::{KvDocumentBuilder, KvDocumentDraft};
use crate::format::token::TokenCodec;
use crate::model::kv_enc::header::KvHeader;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::Result;

use super::super::entry_codec::detect_token_codec;

pub(crate) fn build_unsigned_from_verified(
    verified: &VerifiedKvEncDocument,
    head: KvHeader,
    override_codec: Option<TokenCodec>,
    debug: bool,
) -> Result<KvDocumentDraft> {
    let doc = verified.document();
    let token_codec = detect_token_codec(doc.lines(), override_codec);
    KvDocumentBuilder::from_document(head, None, doc, token_codec, debug)
        .map(|builder| builder.build())
}

pub(crate) fn sign_unsigned_with_key_context(
    unsigned: KvDocumentDraft,
    master_key: &MasterKey,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<String> {
    let signing = build_signing_context(key_ctx, debug)?;
    super::super::sign::sign_unsigned_kv_document(unsigned, master_key, &signing)
}

pub(crate) fn unwrap_master_key_from_verified(
    verified: &VerifiedKvEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<MasterKey> {
    let doc = verified.document();
    let master_key = unwrap_master_key_for_kv_with_context(
        &doc.head.sid,
        &doc.wrap.wrap,
        member_handle,
        key_ctx,
        debug,
    )
    .map(|result| result.value)?;
    verify_kv_key_possession(verified, master_key, debug).map(|proof| proof.into_master_key())
}
