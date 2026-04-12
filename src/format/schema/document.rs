// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Schema-aware parsers for SecretEnv JSON documents and JSON tokens.

use crate::format::schema::validator::{embedded_validator, Validator};
use crate::format::token::decode_token_bytes;
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::model::signature::ArtifactSignature;
use crate::support::fs::load_text_with_limit;
use crate::support::json_limits::validate_json_limits;
use crate::support::limits::validate_wrap_count;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::path::Path;

type ValidateJsonFn = fn(&Validator, &Value) -> Result<()>;

pub fn parse_public_key_str(content: &str, source_name: &str) -> Result<PublicKey> {
    parse_json_document_str(
        content,
        source_name,
        "PublicKey",
        Validator::validate_public_key,
    )
}

pub fn parse_public_key_bytes(bytes: &[u8], source_name: &str) -> Result<PublicKey> {
    parse_json_document_bytes(
        bytes,
        source_name,
        "PublicKey",
        Validator::validate_public_key,
    )
}

pub fn parse_public_key_file(path: &Path) -> Result<PublicKey> {
    parse_json_document_file(path, "PublicKey", Validator::validate_public_key)
}

pub fn parse_private_key_str(content: &str, source_name: &str) -> Result<PrivateKey> {
    parse_json_document_str(
        content,
        source_name,
        "PrivateKey",
        Validator::validate_private_key,
    )
}

pub fn parse_private_key_bytes(bytes: &[u8], source_name: &str) -> Result<PrivateKey> {
    parse_json_document_bytes(
        bytes,
        source_name,
        "PrivateKey",
        Validator::validate_private_key,
    )
}

pub fn parse_private_key_file(path: &Path) -> Result<PrivateKey> {
    parse_json_document_file(path, "PrivateKey", Validator::validate_private_key)
}

pub fn parse_file_enc_str(content: &str, source_name: &str) -> Result<FileEncDocument> {
    let doc = parse_json_document_str(
        content,
        source_name,
        "FileEncDocument",
        Validator::validate_file_enc_document,
    )?;
    validate_file_enc_limits(doc)
}

pub fn parse_file_enc_bytes(bytes: &[u8], source_name: &str) -> Result<FileEncDocument> {
    let doc = parse_json_document_bytes(
        bytes,
        source_name,
        "FileEncDocument",
        Validator::validate_file_enc_document,
    )?;
    validate_file_enc_limits(doc)
}

pub fn parse_file_enc_file(path: &Path) -> Result<FileEncDocument> {
    let doc = parse_json_document_file(
        path,
        "FileEncDocument",
        Validator::validate_file_enc_document,
    )?;
    validate_file_enc_limits(doc)
}

pub fn parse_kv_head_token(token: &str) -> Result<KvHeader> {
    parse_json_token(token, "HEAD token", Validator::validate_kv_head)
}

pub fn parse_kv_wrap_token(token: &str) -> Result<KvWrap> {
    let wrap = parse_json_token(token, "WRAP token", Validator::validate_kv_wrap)?;
    validate_kv_wrap_limits(wrap)
}

pub fn parse_kv_entry_token(token: &str) -> Result<KvEntryValue> {
    parse_json_token(token, "KV entry token", Validator::validate_kv_entry)
}

pub fn parse_kv_signature_token(token: &str) -> Result<ArtifactSignature> {
    parse_json_token(token, "SIG token", Validator::validate_artifact_signature)
}

fn parse_json_document_file<T>(path: &Path, kind: &str, validate: ValidateJsonFn) -> Result<T>
where
    T: DeserializeOwned,
{
    let source_name = display_path_relative_to_cwd(path);
    let subject = format!("{} file", kind);
    let content = load_text_with_limit(path, MAX_JSON_DOCUMENT_READ_SIZE, &subject)?;
    parse_json_document_str(&content, &source_name, kind, validate)
}

fn parse_json_document_str<T>(
    content: &str,
    source_name: &str,
    kind: &str,
    validate: ValidateJsonFn,
) -> Result<T>
where
    T: DeserializeOwned,
{
    parse_json_document_bytes(content.as_bytes(), source_name, kind, validate)
}

fn parse_json_document_bytes<T>(
    bytes: &[u8],
    source_name: &str,
    kind: &str,
    validate: ValidateJsonFn,
) -> Result<T>
where
    T: DeserializeOwned,
{
    validate_json_limits(bytes)?;
    let value = parse_json_value(bytes, source_name, kind)?;
    validate(embedded_validator()?, &value)?;
    deserialize_json_value(value, source_name, kind)
}

fn parse_json_token<T>(token: &str, token_name: &str, validate: ValidateJsonFn) -> Result<T>
where
    T: DeserializeOwned,
{
    let (bytes, _) = decode_token_bytes(token, false, Some(token_name))?;
    validate_json_limits(&bytes)?;
    let value = parse_json_value(&bytes, token_name, token_name)?;
    validate(embedded_validator()?, &value)?;
    deserialize_json_value(value, token_name, token_name)
}

fn parse_json_value(bytes: &[u8], source_name: &str, kind: &str) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|e| Error::Parse {
        message: format!("Failed to parse {} from {}: {}", kind, source_name, e),
        source: Some(Box::new(e)),
    })
}

fn deserialize_json_value<T>(value: Value, source_name: &str, kind: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|e| Error::Parse {
        message: format!("Failed to deserialize {} from {}: {}", kind, source_name, e),
        source: Some(Box::new(e)),
    })
}

fn validate_file_enc_limits(doc: FileEncDocument) -> Result<FileEncDocument> {
    validate_wrap_count(doc.protected.wrap.len(), "FileEncDocument")?;
    Ok(doc)
}

fn validate_kv_wrap_limits(wrap: KvWrap) -> Result<KvWrap> {
    validate_wrap_count(wrap.wrap.len(), "WRAP token")?;
    Ok(wrap)
}
