// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc format parser/writer
//!
//! Line-oriented format:
//! ```text
//! :SECRETENV_KV 6
//! :HEAD <base64url(jcs(KVFileHeader@6))>
//! :WRAP <base64url(jcs(KVFileWrap@6))>
//! KEY1 <base64url(jcs(EncryptedKVValue@6))>
//! KEY2 <base64url(jcs(EncryptedKVValue@6))>
//! :SIG <base64url(jcs(KVFileSignature@6))>
//! ```
//!
//! Diff-friendly: Unchanged lines preserve exact byte representation
//! Control lines start with `:` prefix, separator is space (0x20)

pub mod canonical;
pub mod parser;
pub mod writer;
