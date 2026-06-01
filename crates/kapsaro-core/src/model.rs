// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Data models for kapsaro v3 documents
//!
//! This module contains the serde-serializable structs for v3 document types:
//! - PublicKey
//! - PrivateKey
//! - FileEncDocument
//! - KvEncDocument
//! - Common types (WrapItem, etc.)

pub(crate) mod common;
pub(crate) mod file_enc;
pub(crate) mod identity;
pub(crate) mod kv_enc;
pub(crate) mod private_key;
pub(crate) mod public_key;
pub(crate) mod public_key_verified;
pub(crate) mod signature;
pub(crate) mod ssh;
pub(crate) mod trust_store;
pub(crate) mod trust_store_verified;
pub(crate) mod verification;
pub(crate) mod verified;
pub(crate) mod wire;
