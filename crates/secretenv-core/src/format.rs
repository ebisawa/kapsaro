// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Format parsers and writers
//!
//! This module contains:
//! - detection: Automatic input type detection
//! - file: file-enc canonicalization helpers
//! - jcs: JCS (JSON Canonicalization Scheme) normalization (RFC 8785) and token serialization
//! - kv: KV format modules (dotenv and kv-enc)

pub(crate) mod content;
pub(crate) mod detection;
pub(crate) mod error;
pub(crate) mod file;
pub(crate) mod jcs;
pub(crate) mod kid;
pub(crate) mod kv;
pub(crate) mod schema;
pub(crate) mod token;
pub(crate) mod trust_store;

pub use error::FormatError;
