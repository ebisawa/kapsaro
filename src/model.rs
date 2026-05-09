// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Data models for secretenv v3 documents
//!
//! This module contains the serde-serializable structs for v3 document types:
//! - PublicKey
//! - PrivateKey
//! - FileEncDocument
//! - KvEncDocument
//! - Common types (WrapItem, etc.)

pub mod common;
pub mod file_enc;
pub mod identity;
pub mod kv_enc;
pub mod private_key;
pub mod public_key;
pub mod public_key_verified;
pub mod signature;
pub mod ssh;
pub mod trust_store;
pub mod trust_store_verified;
pub mod verification;
pub mod verified;
pub mod wire;
