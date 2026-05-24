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
    let bytes = build_kv_entry_aad_bytes(context::AAD_KV_ENTRY_PAYLOAD_V9, sid, key)?;
    Ok(Aad::from(bytes))
}

pub fn build_file_payload_aad(protected: &FilePayloadHeader) -> Result<Aad> {
    let value = serde_json::to_value(protected)?;
    let bytes = jcs::normalize_to_bytes(&value)?;
    Ok(Aad::from(bytes))
}

pub fn build_kv_wrap_info(sid: &Uuid, kid: &str) -> Result<Info> {
    let bytes = build_wrap_info_bytes(context::HPKE_INFO_KV_WRAP_V9, sid, kid)?;
    Ok(Info::from(bytes))
}

pub fn build_file_wrap_info(sid: &Uuid, kid: &str) -> Result<Info> {
    let bytes = build_wrap_info_bytes(context::HPKE_INFO_FILE_WRAP_V7, sid, kid)?;
    Ok(Info::from(bytes))
}

pub fn build_file_key_schedule_salt(sid: &Uuid) -> Result<Vec<u8>> {
    build_sid_context_bytes(context::HKDF_SALT_FILE_V7, sid)
}

pub fn build_kv_key_schedule_salt(sid: &Uuid) -> Result<Vec<u8>> {
    build_sid_context_bytes(context::HKDF_SALT_KV_V9, sid)
}

pub fn build_file_content_key_info(sid: &Uuid) -> Result<Info> {
    let bytes = build_sid_context_bytes(context::HKDF_INFO_FILE_CONTENT_KEY_V7, sid)?;
    Ok(Info::from(bytes))
}

pub fn build_file_mac_key_info(sid: &Uuid) -> Result<Info> {
    let bytes = build_sid_context_bytes(context::HKDF_INFO_FILE_MAC_KEY_V7, sid)?;
    Ok(Info::from(bytes))
}

pub fn build_kv_cek_info(sid: &Uuid, key: &str, nonce: &str) -> Result<Info> {
    let bytes = build_kv_cek_info_bytes(context::HKDF_INFO_KV_CEK_V9, sid, key, nonce)?;
    Ok(Info::from(bytes))
}

pub fn build_kv_mac_key_info(sid: &Uuid) -> Result<Info> {
    let bytes = build_sid_context_bytes(context::HKDF_INFO_KV_MAC_KEY_V9, sid)?;
    Ok(Info::from(bytes))
}

fn build_sid_context_bytes(protocol: &str, sid: &Uuid) -> Result<Vec<u8>> {
    normalize_context_json(json!({
        "p": protocol,
        "sid": sid
    }))
}

fn build_wrap_info_bytes(protocol: &str, sid: &Uuid, kid: &str) -> Result<Vec<u8>> {
    normalize_context_json(json!({
        "p": protocol,
        "sid": sid,
        "kid": kid
    }))
}

fn build_kv_entry_aad_bytes(protocol: &str, sid: &Uuid, key: &str) -> Result<Vec<u8>> {
    normalize_context_json(json!({
        "p": protocol,
        "sid": sid,
        "k": key
    }))
}

fn build_kv_cek_info_bytes(protocol: &str, sid: &Uuid, key: &str, nonce: &str) -> Result<Vec<u8>> {
    normalize_context_json(json!({
        "p": protocol,
        "sid": sid,
        "k": key,
        "nonce": nonce
    }))
}

fn normalize_context_json(value: serde_json::Value) -> Result<Vec<u8>> {
    jcs::normalize_to_bytes(&value)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_envelope_binding_test.rs"]
mod tests;
