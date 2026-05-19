// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SecretEnv envelope binding bytes.

use crate::crypto::types::data::{Aad, Info};
use crate::format::jcs;
use crate::model::file_enc::FilePayloadHeader;
use crate::model::wire::context;
use crate::Result;
use serde_json::json;
use uuid::Uuid;

pub fn build_kv_entry_aad(sid: &Uuid, key: &str) -> Result<Aad> {
    let bytes = jcs::normalize_to_bytes(&json!({
        "p": context::AAD_KV_ENTRY_PAYLOAD_V7,
        "sid": sid,
        "k": key
    }))?;
    Ok(Aad::from(bytes))
}

pub fn build_file_payload_aad(protected: &FilePayloadHeader) -> Result<Aad> {
    let value = serde_json::to_value(protected)?;
    let bytes = jcs::normalize_to_bytes(&value)?;
    Ok(Aad::from(bytes))
}

pub fn build_kv_wrap_info(sid: &Uuid, kid: &str) -> Result<Info> {
    let bytes = jcs::normalize_to_bytes(&json!({
        "p": context::HPKE_INFO_KV_WRAP_V7,
        "sid": sid,
        "kid": kid
    }))?;
    Ok(Info::from(bytes))
}

pub fn build_file_wrap_info(sid: &Uuid, kid: &str) -> Result<Info> {
    let bytes = jcs::normalize_to_bytes(&json!({
        "p": context::HPKE_INFO_FILE_WRAP_V5,
        "sid": sid,
        "kid": kid
    }))?;
    Ok(Info::from(bytes))
}

pub fn build_kv_cek_info(sid: &Uuid, key: &str) -> Result<Info> {
    let bytes = jcs::normalize_to_bytes(&json!({
        "p": context::HKDF_INFO_KV_CEK_V7,
        "sid": sid,
        "k": key
    }))?;
    Ok(Info::from(bytes))
}
