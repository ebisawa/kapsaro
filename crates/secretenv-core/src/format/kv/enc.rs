// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc format parser/writer
//!
//! Line-oriented format:
//! ```text
//! :SECRETENV_KV 7
//! :HEAD <base64url(jcs(KVFileHeader@7))>
//! :WRAP <base64url(jcs(KVFileWrap@7))>
//! KEY1 <base64url(jcs(EncryptedKVValue@7))>
//! KEY2 <base64url(jcs(EncryptedKVValue@7))>
//! :SIG <base64url(jcs(KVFileSignature@7))>
//! ```
//!
//! Diff-friendly: Unchanged lines preserve exact byte representation
//! Control lines start with `:` prefix, separator is space (0x20)

pub mod canonical;
pub mod parser;
pub mod writer;
