// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV format modules
//!
//! This module provides:
//! - dotenv: Dotenv format parser
//! - enc: KV-enc format parser/writer

pub mod document;
pub mod dotenv;
pub mod enc;

/// Header line prefix with colon: `:KAPSARO_KV `.
pub const HEADER_LINE_PREFIX: &str = ":KAPSARO_KV ";
/// Header line for v1: `:KAPSARO_KV 1`.
pub const HEADER_LINE_V1: &str = ":KAPSARO_KV 1";

/// File extension for kv-enc files.
pub const KV_ENC_EXTENSION: &str = ".kvenc";
/// Default base name for kv-enc files.
pub const DEFAULT_KV_ENC_BASENAME: &str = "default";
