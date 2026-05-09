// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON Schema validator.

use crate::model::wire::format::{FILE_ENC_V4, PRIVATE_KEY_V6, PUBLIC_KEY_V5};
use crate::support::fs::load_text;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use jsonschema::error::ValidationErrorKind;
use jsonschema::ValidationError;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::LazyLock;

const MAX_SCHEMA_ERROR_REASONS: usize = 5;

const EMBEDDED_SCHEMA: &str = include_str!("../../../schemas/secretenv_schema.json");
const EMBEDDED_TRUST_SCHEMA: &str =
    include_str!("../../../schemas/secretenv_trust_local_schema.json");

static EMBEDDED_VALIDATOR: LazyLock<std::result::Result<Validator, String>> = LazyLock::new(|| {
    let schema_json: Value = serde_json::from_str(EMBEDDED_SCHEMA)
        .map_err(|e| format!("Failed to parse embedded schema: {}", e))?;
    Validator::from_schema(schema_json)
        .map_err(|e| format!("Failed to compile embedded schema: {}", e))
});

static EMBEDDED_TRUST_VALIDATOR: LazyLock<std::result::Result<Validator, String>> =
    LazyLock::new(|| {
        let schema_json: Value = serde_json::from_str(EMBEDDED_TRUST_SCHEMA)
            .map_err(|e| format!("Failed to parse embedded trust schema: {}", e))?;
        Validator::from_schema(schema_json)
            .map_err(|e| format!("Failed to compile embedded trust schema: {}", e))
    });

pub fn load_embedded_validator() -> Result<&'static Validator> {
    EMBEDDED_VALIDATOR.as_ref().map_err(|e| Error::Schema {
        message: e.clone(),
        source: None,
    })
}

/// Get the embedded Trust Store schema validator.
pub fn load_embedded_trust_validator() -> Result<&'static Validator> {
    EMBEDDED_TRUST_VALIDATOR
        .as_ref()
        .map_err(|e| Error::Schema {
            message: e.clone(),
            source: None,
        })
}

pub struct Validator {
    schema: jsonschema::Validator,
}

impl Validator {
    pub fn new() -> Result<Self> {
        let schema_json = Self::load_schema_from_paths("secretenv_schema.json")?;
        Self::from_schema(schema_json)
    }

    pub fn from_schema(schema_json: Value) -> Result<Self> {
        let compiled = jsonschema::draft202012::options()
            .build(&schema_json)
            .map_err(|e| Error::Schema {
                message: format!("Failed to compile schema: {}", e),
                source: Some(Box::new(e)),
            })?;

        Ok(Self { schema: compiled })
    }

    pub fn load_schema_from_paths(filename: &str) -> Result<Value> {
        let possible_paths = [
            PathBuf::from("schemas").join(filename),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("schemas")
                .join(filename),
        ];

        for path in &possible_paths {
            if path.exists() {
                let content = load_text(path)?;
                return serde_json::from_str(&content).map_err(|e| Error::Parse {
                    message: format!(
                        "Failed to parse schema file {}: {}",
                        format_path_relative_to_cwd(path),
                        e
                    ),
                    source: Some(Box::new(e)),
                });
            }
        }

        Err(Error::NotFound {
            message: format!("Schema file not found: {}", filename),
        })
    }

    pub fn validate_public_key(&self, doc: &Value) -> Result<()> {
        self.validate(doc, PUBLIC_KEY_V5)
    }

    pub fn validate_private_key(&self, doc: &Value) -> Result<()> {
        self.validate(doc, PRIVATE_KEY_V6)
    }

    pub fn validate_file_enc_document(&self, doc: &Value) -> Result<()> {
        self.validate(doc, FILE_ENC_V4)
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
        .ok_or_else(|| Error::Schema {
            message: build_schema_error_message(vec![
                "required field format is missing or not a string".to_string(),
            ]),
            source: None,
        })?;

        if format != expected_format {
            return Err(Error::Schema {
                message: build_schema_error_message(vec![format!(
                    "unsupported document format: expected {}",
                    expected_format
                )]),
                source: None,
            });
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

        Err(Error::Schema {
            message: build_schema_error_message(messages),
            source: None,
        })
    }
}

fn build_schema_error_message(reasons: Vec<String>) -> String {
    match reasons.as_slice() {
        [] => "Invalid secretenv document".to_string(),
        [reason] => format!("Invalid secretenv document\nReason: {}", reason),
        _ => build_multi_reason_schema_error_message(reasons),
    }
}

fn build_multi_reason_schema_error_message(reasons: Vec<String>) -> String {
    let mut message = "Invalid secretenv document\nReasons:".to_string();
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
