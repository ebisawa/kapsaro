// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Schema-aware parsers for Kapsaro JSON documents and JSON tokens.

use crate::format::schema::validator::{load_embedded_validator, SchemaTarget, Validator};
use crate::format::token::decode_token_bytes;
use crate::format::wrap::validate_wrap_items;
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::model::signature::ArtifactSignature;
use crate::model::trust_store::TrustStoreDocument;
use crate::support::json_limits::validate_json_limits;
use crate::{Error, Result};
use serde::de::{DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;

type ValidateJsonFn = fn(&Validator, &Value) -> Result<()>;

pub fn parse_public_key_str(content: &str, source_name: &str) -> Result<PublicKey> {
    parse_json_document_str(
        content,
        source_name,
        "PublicKey",
        SchemaTarget::PublicKey,
        Validator::validate_public_key,
    )
}

pub fn parse_private_key_str(content: &str, source_name: &str) -> Result<PrivateKey> {
    parse_json_document_str(
        content,
        source_name,
        "PrivateKey",
        SchemaTarget::PrivateKey,
        Validator::validate_private_key,
    )
}

pub fn parse_private_key_bytes(bytes: &[u8], source_name: &str) -> Result<PrivateKey> {
    parse_json_document_bytes(
        bytes,
        source_name,
        "PrivateKey",
        SchemaTarget::PrivateKey,
        Validator::validate_private_key,
    )
}

pub fn parse_file_enc_str(content: &str, source_name: &str) -> Result<FileEncDocument> {
    let doc = parse_json_document_str(
        content,
        source_name,
        "FileEncDocument",
        SchemaTarget::FileEnc,
        Validator::validate_file_enc_document,
    )?;
    validate_file_enc_limits(doc)
}

pub fn parse_trust_store_str(content: &str, source_name: &str) -> Result<TrustStoreDocument> {
    parse_json_document_str(
        content,
        source_name,
        "TrustStoreDocument",
        SchemaTarget::LocalTrust,
        Validator::validate_trust_store,
    )
}

pub fn parse_kv_head_token(token: &str) -> Result<KvHeader> {
    parse_kv_head_token_with_source(token, "HEAD token")
}

pub fn parse_kv_wrap_token(token: &str) -> Result<KvWrap> {
    parse_kv_wrap_token_with_source(token, "WRAP token")
}

pub fn parse_kv_entry_token(token: &str) -> Result<KvEntryValue> {
    parse_kv_entry_token_with_source(token, "KV entry token")
}

pub fn parse_kv_signature_token(token: &str) -> Result<ArtifactSignature> {
    parse_kv_signature_token_with_source(token, "SIG token")
}

pub fn parse_kv_head_token_with_source(token: &str, source_name: &str) -> Result<KvHeader> {
    parse_json_token(
        token,
        "HEAD token",
        source_name,
        SchemaTarget::KvHead,
        Validator::validate_kv_head,
    )
}

pub fn parse_kv_wrap_token_with_source(token: &str, source_name: &str) -> Result<KvWrap> {
    let wrap = parse_json_token(
        token,
        "WRAP token",
        source_name,
        SchemaTarget::KvWrap,
        Validator::validate_kv_wrap,
    )?;
    validate_kv_wrap_limits(wrap)
}

pub fn parse_kv_entry_token_with_source(token: &str, source_name: &str) -> Result<KvEntryValue> {
    parse_json_token(
        token,
        "KV entry token",
        source_name,
        SchemaTarget::KvEntry,
        Validator::validate_kv_entry,
    )
}

pub fn parse_kv_signature_token_with_source(
    token: &str,
    source_name: &str,
) -> Result<ArtifactSignature> {
    parse_json_token(
        token,
        "SIG token",
        source_name,
        SchemaTarget::ArtifactSignature,
        Validator::validate_artifact_signature,
    )
}

fn parse_json_document_str<T>(
    content: &str,
    source_name: &str,
    kind: &str,
    target: SchemaTarget,
    validate: ValidateJsonFn,
) -> Result<T>
where
    T: DeserializeOwned,
{
    parse_json_document_bytes(content.as_bytes(), source_name, kind, target, validate)
}

fn parse_json_document_bytes<T>(
    bytes: &[u8],
    source_name: &str,
    kind: &str,
    target: SchemaTarget,
    validate: ValidateJsonFn,
) -> Result<T>
where
    T: DeserializeOwned,
{
    validate_json_limits(bytes)?;
    let value = parse_json_value(bytes, source_name, kind)?;
    validate(load_embedded_validator(target)?, &value)
        .map_err(|e| add_source_to_schema_error(e, source_name))?;
    deserialize_json_value(value, source_name, kind)
}

fn parse_json_token<T>(
    token: &str,
    token_name: &str,
    source_name: &str,
    target: SchemaTarget,
    validate: ValidateJsonFn,
) -> Result<T>
where
    T: DeserializeOwned,
{
    let (bytes, _) = decode_token_bytes(token, false, Some(token_name))?;
    validate_json_limits(&bytes)?;
    let value = parse_json_value(&bytes, source_name, token_name)?;
    validate(load_embedded_validator(target)?, &value)
        .map_err(|e| add_source_to_schema_error(e, source_name))?;
    deserialize_json_value(value, source_name, token_name)
}

fn parse_json_value(bytes: &[u8], source_name: &str, kind: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJsonValue
        .deserialize(&mut deserializer)
        .map_err(|e| {
            Error::build_parse_error_with_source(
                format!("Failed to parse {} from {}: {}", kind, source_name, e),
                e,
            )
        })?;
    deserializer.end().map_err(|e| {
        Error::build_parse_error_with_source(
            format!("Failed to parse {} from {}: {}", kind, source_name, e),
            e,
        )
    })?;
    Ok(value)
}

struct UniqueJsonValue;

impl<'de> DeserializeSeed<'de> for UniqueJsonValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object member names")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueJsonValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = BTreeSet::new();
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !names.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON member name '{}'",
                    key
                )));
            }
            let value = map.next_value_seed(UniqueJsonValue)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

fn deserialize_json_value<T>(value: Value, source_name: &str, kind: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|e| {
        Error::build_parse_error_with_source(
            format!("Failed to deserialize {} from {}: {}", kind, source_name, e),
            e,
        )
    })
}

fn add_source_to_schema_error(error: Error, source_name: &str) -> Error {
    if error.kind() == crate::ErrorKind::Schema {
        return Error::build_schema_error(insert_schema_source(
            error.format_user_message(),
            source_name,
        ));
    }
    error
}

fn insert_schema_source(message: &str, source_name: &str) -> String {
    if source_name.is_empty() {
        return message.to_string();
    }

    let source_line = format!("Source: {}", source_name);
    if message.lines().any(|line| line == source_line) {
        return message.to_string();
    }

    if let Some(rest) = message.strip_prefix("Invalid kapsaro document\n") {
        return format!("Invalid kapsaro document\n{}\n{}", source_line, rest);
    }
    if message == "Invalid kapsaro document" {
        return format!("{}\n{}", message, source_line);
    }
    format!("{}\n{}", message, source_line)
}

fn validate_file_enc_limits(doc: FileEncDocument) -> Result<FileEncDocument> {
    validate_wrap_items(&doc.protected.wrap, "FileEncDocument")?;
    Ok(doc)
}

fn validate_kv_wrap_limits(wrap: KvWrap) -> Result<KvWrap> {
    validate_wrap_items(&wrap.wrap, "WRAP token")?;
    Ok(wrap)
}
