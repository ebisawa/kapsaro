// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Format parsers and writers
//!
//! This module contains:
//! - detection: Automatic input type detection
//! - file: file-enc canonicalization helpers
//! - jcs: JCS (JSON Canonicalization Scheme) normalization (RFC 8785) and token serialization
//! - kv: KV format modules (dotenv and kv-enc)

pub mod content;
pub mod detection;
pub mod error;
pub mod file;
pub mod jcs;
pub mod kid;
pub mod kv;
pub mod schema;
pub mod token;
pub mod trust_store;

pub use error::FormatError;
