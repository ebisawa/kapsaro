// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc format parser/writer
//!
//! Line-oriented format:
//! ```text
//! :KAPSARO_KV 1
//! :HEAD <base64url(jcs(KVFileHeader@1))>
//! :WRAP <base64url(jcs(KVFileWrap@1))>
//! KEY1 <base64url(jcs(EncryptedKVValue@1))>
//! KEY2 <base64url(jcs(EncryptedKVValue@1))>
//! :SIG <base64url(jcs(KVFileSignature@1))>
//! ```
//!
//! Diff-friendly: Unchanged lines preserve exact byte representation
//! Control lines start with `:` prefix, separator is space (0x20)

pub mod canonical;
pub mod parser;
pub mod writer;
