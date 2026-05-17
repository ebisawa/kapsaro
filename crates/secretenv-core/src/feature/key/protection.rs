// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH-based private key protection (encryption/decryption).

pub mod binding;
pub mod encryption;
pub mod key_derivation;
mod material;
pub mod password_encryption;
pub mod password_key_derivation;
