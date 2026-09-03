// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::KvDocumentBuilder;
use crate::format::kv::document::draft::{KvDocumentEntry, WrapSource};
use crate::format::kv::document::KvDocumentDraft;
use crate::format::schema::document::parse_kv_entry_token_with_source;
use crate::format::token::TokenCodec;
use crate::model::common::WrapItem;
use crate::model::kv_enc::document::{KvEncDocument, KvEncEntry, KvFileSignature};
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvFileAlgorithm, KvHeader, KvWrap};
use crate::model::kv_enc::line::{KvEncLine, KvEncVersion};
use crate::model::signature::KeyPossessionProof;
use crate::model::wire::algorithm;
use crate::test_utils::keygen_helpers::build_dummy_public_key;
use std::collections::HashMap;
use uuid::Uuid;

const SAMPLE_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

fn sample_head() -> KvHeader {
    KvHeader {
        sid: Uuid::nil(),
        alg: KvFileAlgorithm {
            aead: "xchacha20-poly1305".to_string(),
        },
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn sample_wrap() -> KvWrap {
    KvWrap {
        wrap: vec![WrapItem {
            recipient_handle: "alice@example.com".to_string(),
            kid: SAMPLE_KID.to_string(),
            alg: "hpke-32-1-3".to_string(),
            enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        }],
        removed_recipients: None,
    }
}

fn encode_wrap_token(wrap: &KvWrap) -> String {
    TokenCodec::encode(TokenCodec::JsonJcs, wrap).unwrap()
}

fn sample_entry_value(_key: &str, disclosed: bool) -> KvEntryValue {
    KvEntryValue {
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        disclosed,
    }
}

fn encode_entry(val: &KvEntryValue) -> String {
    TokenCodec::encode(TokenCodec::JsonJcs, val).unwrap()
}

fn entry_keys(doc: &KvDocumentDraft) -> Vec<&str> {
    doc.entries.iter().map(|entry| entry.key()).collect()
}

fn kv_line(key: &str, value: &KvEntryValue) -> KvEncLine {
    KvEncLine::KV {
        key: key.to_string(),
        token: encode_entry(value),
    }
}

fn sample_signature() -> KvFileSignature {
    KvFileSignature {
        alg: algorithm::SIGNATURE_ED25519.to_string(),
        kid: SAMPLE_KID.to_string(),
        signer_pub: build_dummy_public_key(SAMPLE_KID),
        mac: KeyPossessionProof::parse("hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap(),
        sig: String::new(),
    }
}

/// Assemble the parsed document a case hands to the builder.
///
/// The builder reads the entries a parse already decoded, so each case states
/// its lines together with the entry values those lines carry.
fn sample_document(lines: Vec<KvEncLine>, entries: &[(&str, KvEntryValue)]) -> KvEncDocument {
    let wrap_token = lines
        .iter()
        .find_map(|line| match line {
            KvEncLine::Wrap { token } => Some(token.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let doc_entries = entries
        .iter()
        .map(|(key, value)| KvEncEntry::new(key.to_string(), encode_entry(value), value.clone()))
        .collect();

    KvEncDocument::new(
        lines,
        sample_head(),
        sample_wrap(),
        wrap_token,
        doc_entries,
        sample_signature(),
    )
}

#[test]
fn test_kv_document_entry_preserved_accessors() {
    let e = KvDocumentEntry::Preserved {
        key: "FOO".to_string(),
        token: "tok".to_string(),
        value: sample_entry_value("FOO", false),
    };
    assert_eq!(e.key(), "FOO");
    assert_eq!(e.token(), "tok");
}

#[test]
fn test_kv_document_entry_encoded_accessors() {
    let e = KvDocumentEntry::Encoded {
        key: "BAR".to_string(),
        token: "tok2".to_string(),
    };
    assert_eq!(e.key(), "BAR");
    assert_eq!(e.token(), "tok2");
}

#[test]
fn test_wrap_source_decoded_data() {
    let w = WrapSource::decoded(sample_wrap());
    assert_eq!(w.data().wrap.len(), 1);
    assert_eq!(w.token(), None);
}

#[test]
fn test_wrap_source_raw_keeps_the_original_token() {
    let w = WrapSource::raw(sample_wrap(), "raw_tok".to_string());
    assert_eq!(w.data().wrap.len(), 1);
    assert_eq!(w.token(), Some("raw_tok"));
}

/// Mutating the data invalidates the token it was parsed from, so the token
/// must be dropped rather than re-serialized alongside stale data.
#[test]
fn test_wrap_source_data_mut_drops_the_original_token() {
    let mut w = WrapSource::raw(sample_wrap(), "raw_tok".to_string());

    let _d = w.data_mut();

    assert_eq!(w.token(), None);
}

#[test]
fn test_builder_new_creates_decoded_wrap() {
    let b = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs);
    let doc = b.build();
    assert_eq!(doc.wrap.token(), None);
    assert!(doc.entries.is_empty());
}

#[test]
fn test_builder_from_document_with_some_wrap() {
    let wrap = sample_wrap();
    let wrap_tok = encode_wrap_token(&wrap);
    let entry = sample_entry_value("A", false);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V1,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap { token: wrap_tok },
        kv_line("A", &entry),
    ];
    let document = sample_document(lines, &[("A", entry.clone())]);
    let b = KvDocumentBuilder::from_document(
        sample_head(),
        Some(wrap.clone()),
        &document,
        TokenCodec::JsonJcs,
    )
    .unwrap();
    let doc = b.build();
    assert_eq!(doc.wrap.token(), None);
    assert_eq!(doc.entries.len(), 1);
    assert_eq!(doc.entries[0].key(), "A");
}

#[test]
fn test_builder_from_document_with_none_wrap_decodes_raw() {
    let wrap = sample_wrap();
    let wrap_tok = encode_wrap_token(&wrap);
    let entry = sample_entry_value("B", false);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V1,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: wrap_tok.clone(),
        },
        kv_line("B", &entry),
    ];
    let document = sample_document(lines, &[("B", entry.clone())]);
    let b = KvDocumentBuilder::from_document(sample_head(), None, &document, TokenCodec::JsonJcs)
        .unwrap();
    let doc = b.build();
    assert!(doc.wrap.token().is_some());
    assert_eq!(doc.entries.len(), 1);
}

#[test]
fn test_builder_with_entries_appends() {
    let b = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs);
    let doc = b
        .with_entries(vec![("X".to_string(), "tx".to_string())])
        .build();
    assert_eq!(doc.entries.len(), 1);
    assert!(matches!(&doc.entries[0], KvDocumentEntry::Encoded { .. }));
}

#[test]
fn test_unsigned_doc_entry_keys() {
    let doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs)
        .with_entries(vec![
            ("A".to_string(), "ta".to_string()),
            ("B".to_string(), "tb".to_string()),
        ])
        .build();
    assert_eq!(entry_keys(&doc), vec!["A", "B"]);
}

#[test]
fn test_unsigned_doc_has_entry() {
    let doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs)
        .with_entries(vec![("K".to_string(), "t".to_string())])
        .build();
    assert!(entry_keys(&doc).contains(&"K"));
    assert!(!entry_keys(&doc).contains(&"X"));
}

#[test]
fn test_unsigned_doc_set_entries_replaces_and_appends() {
    let mut doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs)
        .with_entries(vec![
            ("A".to_string(), "old_a".to_string()),
            ("B".to_string(), "old_b".to_string()),
        ])
        .build();

    let mut entries = HashMap::new();
    entries.insert("A", "new_a");
    entries.insert("C", "new_c");
    doc.set_entries(&entries);

    assert_eq!(doc.entries[0].key(), "A");
    assert_eq!(doc.entries[0].token(), "new_a");
    assert_eq!(doc.entries[1].key(), "B");
    assert_eq!(doc.entries[1].token(), "old_b");
    assert_eq!(doc.entries[2].key(), "C");
    assert_eq!(doc.entries[2].token(), "new_c");
}

#[test]
fn test_unsigned_doc_unset_entry() {
    let mut doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs)
        .with_entries(vec![
            ("A".to_string(), "ta".to_string()),
            ("B".to_string(), "tb".to_string()),
        ])
        .build();
    doc.unset_entry("A");
    assert_eq!(entry_keys(&doc), vec!["B"]);
}

#[test]
fn test_unsigned_doc_set_updated_at() {
    let mut doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs).build();
    doc.set_updated_at("2026-05-25T00:00:00Z".to_string());
    assert_eq!(doc.head().updated_at, "2026-05-25T00:00:00Z");
}

#[test]
fn test_unsigned_doc_wrap_mut_promotes() {
    let wrap = sample_wrap();
    let wrap_tok = encode_wrap_token(&wrap);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V1,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: wrap_tok.clone(),
        },
    ];
    let document = sample_document(lines, &[]);
    let mut doc =
        KvDocumentBuilder::from_document(sample_head(), None, &document, TokenCodec::JsonJcs)
            .unwrap()
            .build();

    assert!(doc.wrap.token().is_some());
    let _w = doc.wrap_mut();
    assert_eq!(doc.wrap.token(), None);
}

#[test]
fn test_serialize_unsigned_format() {
    let val_a = sample_entry_value("A", false);
    let val_b = sample_entry_value("B", false);
    let doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs)
        .with_entries(vec![
            ("A".to_string(), encode_entry(&val_a)),
            ("B".to_string(), encode_entry(&val_b)),
        ])
        .build();

    let s = doc.serialize_unsigned().unwrap();
    assert!(s.starts_with(":KAPSARO_KV 1\n"));
    assert!(s.contains(":HEAD "));
    assert!(s.contains(":WRAP "));
    assert!(s.contains("A "));
    assert!(s.contains("B "));
    assert!(!s.contains(":SIG"));
}

#[test]
fn test_serialize_unsigned_raw_wrap_passthrough() {
    let wrap = sample_wrap();
    let wrap_tok = encode_wrap_token(&wrap);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V1,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: wrap_tok.clone(),
        },
    ];
    let document = sample_document(lines, &[]);
    let doc = KvDocumentBuilder::from_document(sample_head(), None, &document, TokenCodec::JsonJcs)
        .unwrap()
        .build();

    let s = doc.serialize_unsigned().unwrap();
    assert!(s.contains(&format!(":WRAP {}\n", wrap_tok)));
}

#[test]
fn test_clear_disclosed_flags_clears_disclosed_true() {
    let val_a = sample_entry_value("A", true);
    let val_b = sample_entry_value("B", false);
    let tok_a = encode_entry(&val_a);
    let tok_b = encode_entry(&val_b);

    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V1,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: encode_wrap_token(&sample_wrap()),
        },
        KvEncLine::KV {
            key: "A".to_string(),
            token: tok_a,
        },
        KvEncLine::KV {
            key: "B".to_string(),
            token: tok_b.clone(),
        },
    ];

    let document = sample_document(lines, &[("A", val_a.clone()), ("B", val_b.clone())]);
    let mut doc = KvDocumentBuilder::from_document(
        sample_head(),
        Some(sample_wrap()),
        &document,
        TokenCodec::JsonJcs,
    )
    .unwrap()
    .build();

    doc.clear_disclosed_flags().unwrap();

    assert!(matches!(&doc.entries[0], KvDocumentEntry::Encoded { .. }));
    let decoded_a: KvEntryValue =
        parse_kv_entry_token_with_source(doc.entries[0].token(), "KV entry token").unwrap();
    assert!(!decoded_a.disclosed);

    assert!(matches!(&doc.entries[1], KvDocumentEntry::Preserved { .. }));
    assert_eq!(doc.entries[1].token(), tok_b);
}

#[test]
fn test_clear_disclosed_flags_noop_when_all_false() {
    let val = sample_entry_value("X", false);
    let tok = encode_entry(&val);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V1,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: encode_wrap_token(&sample_wrap()),
        },
        KvEncLine::KV {
            key: "X".to_string(),
            token: tok.clone(),
        },
    ];

    let document = sample_document(lines, &[("X", val.clone())]);
    let mut doc = KvDocumentBuilder::from_document(
        sample_head(),
        Some(sample_wrap()),
        &document,
        TokenCodec::JsonJcs,
    )
    .unwrap()
    .build();

    doc.clear_disclosed_flags().unwrap();
    assert!(matches!(&doc.entries[0], KvDocumentEntry::Preserved { .. }));
}
