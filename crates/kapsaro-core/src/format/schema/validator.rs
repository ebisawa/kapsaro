// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON Schema validator.

use crate::model::wire::format::{FILE_ENC_V1, PRIVATE_KEY_V1, PUBLIC_KEY_V1};
use crate::support::fs::load_text;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use jsonschema::error::ValidationErrorKind;
use jsonschema::ValidationError;
use serde_json::Value;
use std::path::Path;
use std::sync::LazyLock;

const MAX_SCHEMA_ERROR_REASONS: usize = 5;

const COMMON_SCHEMA: &str = include_str!("../../../schemas/kapsaro_common_schema.json");
const PUBLIC_KEY_SCHEMA: &str = include_str!("../../../schemas/kapsaro_public_key_schema.json");
const PRIVATE_KEY_SCHEMA: &str = include_str!("../../../schemas/kapsaro_private_key_schema.json");
const FILE_ENC_SCHEMA: &str = include_str!("../../../schemas/kapsaro_file_enc_schema.json");
const KV_ENC_SCHEMA: &str = include_str!("../../../schemas/kapsaro_kv_enc_schema.json");
const ARTIFACT_SIGNATURE_SCHEMA: &str =
    include_str!("../../../schemas/kapsaro_artifact_signature_schema.json");
const LOCAL_TRUST_SCHEMA: &str = include_str!("../../../schemas/kapsaro_local_trust_schema.json");

const SCHEMA_RESOURCE_CONTENTS: &[SchemaResourceContent] = &[
    SchemaResourceContent {
        uri: "kapsaro_common_schema.json",
        content: COMMON_SCHEMA,
    },
    SchemaResourceContent {
        uri: "kapsaro_public_key_schema.json",
        content: PUBLIC_KEY_SCHEMA,
    },
    SchemaResourceContent {
        uri: "kapsaro_private_key_schema.json",
        content: PRIVATE_KEY_SCHEMA,
    },
    SchemaResourceContent {
        uri: "kapsaro_file_enc_schema.json",
        content: FILE_ENC_SCHEMA,
    },
    SchemaResourceContent {
        uri: "kapsaro_kv_enc_schema.json",
        content: KV_ENC_SCHEMA,
    },
    SchemaResourceContent {
        uri: "kapsaro_artifact_signature_schema.json",
        content: ARTIFACT_SIGNATURE_SCHEMA,
    },
    SchemaResourceContent {
        uri: "kapsaro_local_trust_schema.json",
        content: LOCAL_TRUST_SCHEMA,
    },
];

static PUBLIC_KEY_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::PublicKey));
static PRIVATE_KEY_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::PrivateKey));
static FILE_ENC_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::FileEnc));
static KV_HEAD_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::KvHead));
static KV_WRAP_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::KvWrap));
static KV_ENTRY_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::KvEntry));
static ARTIFACT_SIGNATURE_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::ArtifactSignature));
static LOCAL_TRUST_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| compile_embedded_target(SchemaTarget::LocalTrust));

pub fn load_embedded_validator(target: SchemaTarget) -> Result<&'static Validator> {
    embedded_validator(target)
        .as_ref()
        .map_err(|e| Error::build_schema_error(e.clone()))
}

/// Get the embedded Trust Store schema validator.
pub fn load_embedded_trust_validator() -> Result<&'static Validator> {
    load_embedded_validator(SchemaTarget::LocalTrust)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaTarget {
    PublicKey,
    PrivateKey,
    FileEnc,
    KvHead,
    KvWrap,
    KvEntry,
    ArtifactSignature,
    LocalTrust,
}

pub struct Validator {
    schema: jsonschema::Validator,
}

impl Validator {
    pub fn for_target(target: SchemaTarget) -> Result<Self> {
        let schema_json = target.load_schema_from_paths()?;
        let resources = load_schema_resources_from_paths()?;
        Self::from_schema_with_resources(schema_json, &resources)
    }

    pub fn from_schema(schema_json: Value) -> Result<Self> {
        Self::from_schema_with_resources(schema_json, &[])
    }

    pub fn from_schema_with_resources(
        schema_json: Value,
        resources: &[(String, Value)],
    ) -> Result<Self> {
        let registry = build_registry(resources)?;
        let compiled = jsonschema::draft202012::options()
            .with_registry(&registry)
            .with_base_uri("kapsaro.schema")
            .build(&schema_json)
            .map_err(|e| {
                Error::build_schema_error_with_source(format!("Failed to compile schema: {}", e), e)
            })?;

        Ok(Self { schema: compiled })
    }

    pub fn load_schema_from_paths(filename: &str) -> Result<Value> {
        load_schema_file(filename)
    }

    pub fn validate_public_key(&self, doc: &Value) -> Result<()> {
        self.validate(doc, PUBLIC_KEY_V1)
    }

    pub fn validate_private_key(&self, doc: &Value) -> Result<()> {
        self.validate(doc, PRIVATE_KEY_V1)
    }

    pub fn validate_file_enc_document(&self, doc: &Value) -> Result<()> {
        self.validate(doc, FILE_ENC_V1)
    }

    pub fn validate_kv_head(&self, doc: &Value) -> Result<()> {
        self.validate_generic(doc)
    }

    pub fn validate_kv_wrap(&self, doc: &Value) -> Result<()> {
        self.validate_generic(doc)
    }

    pub fn validate_kv_entry(&self, doc: &Value) -> Result<()> {
        self.validate_generic(doc)
    }

    pub fn validate_artifact_signature(&self, doc: &Value) -> Result<()> {
        self.validate_generic(doc)
    }

    pub fn validate_trust_store(&self, doc: &Value) -> Result<()> {
        self.validate_generic(doc)
    }

    fn validate(&self, doc: &Value, expected_format: &str) -> Result<()> {
        let format = if doc.get("protected").is_some() {
            doc.get("protected")
                .and_then(|p| p.get("format"))
                .and_then(|f| f.as_str())
        } else {
            doc.get("format").and_then(|f| f.as_str())
        }
        .ok_or_else(|| {
            Error::build_schema_error(build_schema_error_message(vec![
                "required field format is missing or not a string".to_string(),
            ]))
        })?;

        if format != expected_format {
            return Err(Error::build_schema_error(build_schema_error_message(vec![
                format!("unsupported document format: expected {}", expected_format),
            ])));
        }

        self.validate_generic(doc)
    }

    fn validate_generic(&self, doc: &Value) -> Result<()> {
        if self.schema.is_valid(doc) {
            return Ok(());
        }

        let messages: Vec<String> = self
            .schema
            .iter_errors(doc)
            .flat_map(|error| collect_validation_error_reasons(&error))
            .collect();

        Err(Error::build_schema_error(build_schema_error_message(
            messages,
        )))
    }
}

struct SchemaResourceContent {
    uri: &'static str,
    content: &'static str,
}

fn embedded_validator(target: SchemaTarget) -> &'static std::result::Result<Validator, String> {
    match target {
        SchemaTarget::PublicKey => &PUBLIC_KEY_VALIDATOR,
        SchemaTarget::PrivateKey => &PRIVATE_KEY_VALIDATOR,
        SchemaTarget::FileEnc => &FILE_ENC_VALIDATOR,
        SchemaTarget::KvHead => &KV_HEAD_VALIDATOR,
        SchemaTarget::KvWrap => &KV_WRAP_VALIDATOR,
        SchemaTarget::KvEntry => &KV_ENTRY_VALIDATOR,
        SchemaTarget::ArtifactSignature => &ARTIFACT_SIGNATURE_VALIDATOR,
        SchemaTarget::LocalTrust => &LOCAL_TRUST_VALIDATOR,
    }
}

fn compile_embedded_target(target: SchemaTarget) -> std::result::Result<Validator, String> {
    let schema_json = parse_embedded_target_schema(target)?;
    let resources = parse_embedded_schema_resources()?;
    Validator::from_schema_with_resources(schema_json, &resources)
        .map_err(|e| format!("Failed to compile embedded {} schema: {}", target.name(), e))
}

fn parse_embedded_target_schema(target: SchemaTarget) -> std::result::Result<Value, String> {
    match target.embedded_schema_content() {
        Some(content) => parse_embedded_schema(target.filename(), content),
        None => Ok(target.wrapper_schema()),
    }
}

fn parse_embedded_schema(filename: &str, content: &str) -> std::result::Result<Value, String> {
    serde_json::from_str(content)
        .map_err(|e| format!("Failed to parse embedded schema {}: {}", filename, e))
}

fn parse_embedded_schema_resources() -> std::result::Result<Vec<(String, Value)>, String> {
    SCHEMA_RESOURCE_CONTENTS
        .iter()
        .map(|resource| {
            parse_embedded_schema(resource.uri, resource.content)
                .map(|schema| (resource.uri.to_string(), schema))
        })
        .collect()
}

fn load_schema_resources_from_paths() -> Result<Vec<(String, Value)>> {
    SCHEMA_RESOURCE_CONTENTS
        .iter()
        .map(|resource| {
            load_schema_file(resource.uri).map(|schema| (resource.uri.to_string(), schema))
        })
        .collect()
}

fn build_registry(resources: &[(String, Value)]) -> Result<jsonschema::Registry<'_>> {
    let mut registry = jsonschema::Registry::new();
    for (uri, schema) in resources {
        registry = registry.add(uri, schema).map_err(|e| {
            Error::build_schema_error_with_source(
                format!("Failed to register schema resource {}: {}", uri, e),
                e,
            )
        })?;
    }
    registry.prepare().map_err(|e| {
        Error::build_schema_error_with_source(
            format!("Failed to prepare schema registry: {}", e),
            e,
        )
    })
}

fn load_schema_file(filename: &str) -> Result<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(filename);
    if !path.exists() {
        return Err(Error::build_not_found_error(format!(
            "Schema file not found: {}",
            filename
        )));
    }

    let content = load_text(&path)?;
    serde_json::from_str(&content).map_err(|e| {
        Error::build_parse_error_with_source(
            format!(
                "Failed to parse schema file {}: {}",
                format_path_relative_to_cwd(&path),
                e
            ),
            e,
        )
    })
}

impl SchemaTarget {
    pub fn filename(self) -> &'static str {
        match self {
            Self::PublicKey => "kapsaro_public_key_schema.json",
            Self::PrivateKey => "kapsaro_private_key_schema.json",
            Self::FileEnc => "kapsaro_file_enc_schema.json",
            Self::KvHead | Self::KvWrap | Self::KvEntry => "kapsaro_kv_enc_schema.json",
            Self::ArtifactSignature => "kapsaro_artifact_signature_schema.json",
            Self::LocalTrust => "kapsaro_local_trust_schema.json",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::PublicKey => "public key",
            Self::PrivateKey => "private key",
            Self::FileEnc => "file enc",
            Self::KvHead => "kv head",
            Self::KvWrap => "kv wrap",
            Self::KvEntry => "kv entry",
            Self::ArtifactSignature => "artifact signature",
            Self::LocalTrust => "local trust",
        }
    }

    fn embedded_schema_content(self) -> Option<&'static str> {
        match self {
            Self::PublicKey => Some(PUBLIC_KEY_SCHEMA),
            Self::PrivateKey => Some(PRIVATE_KEY_SCHEMA),
            Self::FileEnc => Some(FILE_ENC_SCHEMA),
            Self::KvHead | Self::KvWrap | Self::KvEntry => None,
            Self::ArtifactSignature => Some(ARTIFACT_SIGNATURE_SCHEMA),
            Self::LocalTrust => Some(LOCAL_TRUST_SCHEMA),
        }
    }

    fn load_schema_from_paths(self) -> Result<Value> {
        match self {
            Self::KvHead | Self::KvWrap | Self::KvEntry => Ok(self.wrapper_schema()),
            _ => load_schema_file(self.filename()),
        }
    }

    fn wrapper_schema(self) -> Value {
        let (id, title, target_ref) = match self {
            Self::KvHead => (
                "kapsaro.kv.enc.head.schema.json",
                "kapsaro kv enc head schema",
                "kapsaro_kv_enc_schema.json#/$defs/head",
            ),
            Self::KvWrap => (
                "kapsaro.kv.enc.wrap.schema.json",
                "kapsaro kv enc wrap schema",
                "kapsaro_kv_enc_schema.json#/$defs/wrap",
            ),
            Self::KvEntry => (
                "kapsaro.kv.enc.entry.schema.json",
                "kapsaro kv enc entry schema",
                "kapsaro_kv_enc_schema.json#/$defs/value",
            ),
            _ => unreachable!("non-KV target does not use a wrapper schema"),
        };
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": id,
            "title": title,
            "$ref": target_ref
        })
    }
}

fn build_schema_error_message(reasons: Vec<String>) -> String {
    match reasons.as_slice() {
        [] => "Invalid kapsaro document".to_string(),
        [reason] => format!("Invalid kapsaro document\nReason: {}", reason),
        _ => build_multi_reason_schema_error_message(reasons),
    }
}

fn build_multi_reason_schema_error_message(reasons: Vec<String>) -> String {
    let mut message = "Invalid kapsaro document\nReasons:".to_string();
    let total = reasons.len();
    for reason in reasons.into_iter().take(MAX_SCHEMA_ERROR_REASONS) {
        message.push_str("\n  - ");
        message.push_str(&reason);
    }
    if total > MAX_SCHEMA_ERROR_REASONS {
        message.push_str(&format!(
            "\n  - ... {} more issues omitted",
            total - MAX_SCHEMA_ERROR_REASONS
        ));
    }
    message
}

fn collect_validation_error_reasons(error: &ValidationError<'_>) -> Vec<String> {
    match error.kind() {
        ValidationErrorKind::AnyOf { context }
        | ValidationErrorKind::OneOfNotValid { context }
        | ValidationErrorKind::OneOfMultipleValid { context } => {
            collect_best_context_reasons(context)
                .unwrap_or_else(|| vec![format_validation_error(error)])
        }
        _ => vec![format_validation_error(error)],
    }
}

fn collect_best_context_reasons(context: &[Vec<ValidationError<'static>>]) -> Option<Vec<String>> {
    context
        .iter()
        .filter_map(|branch| {
            let reasons = branch
                .iter()
                .flat_map(collect_validation_error_reasons)
                .collect::<Vec<_>>();
            (!reasons.is_empty()).then_some(reasons)
        })
        .min_by_key(|reasons| reasons.len())
}

fn format_validation_error(error: &ValidationError<'_>) -> String {
    let field_path = format_instance_path(error.instance_path().as_str());
    let reason = error.masked_with("value").to_string();
    format!("{}: {}", field_path, reason)
}

fn format_instance_path(path: &str) -> String {
    if path.is_empty() {
        return "document".to_string();
    }
    path.trim_start_matches('/')
        .split('/')
        .map(unescape_json_pointer_segment)
        .collect::<Vec<_>>()
        .join(".")
}

fn unescape_json_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/format_schema_trust_store_test.rs"]
mod format_schema_trust_store_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/schema_validator_test.rs"]
mod schema_validator_test;
