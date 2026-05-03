// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::KvDocumentBuilder;
use crate::feature::kv::document::{KvDocumentEntry, WrapSource};
use crate::format::schema::document::parse_kv_entry_token;
use crate::format::token::TokenCodec;
use crate::model::common::WrapItem;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::line::{KvEncLine, KvEncVersion};
use secretenv::support::codec::base64_public::encode_base64url_nopad;
use std::collections::HashMap;
use uuid::Uuid;

fn sample_head() -> KvHeader {
    KvHeader {
        sid: Uuid::nil(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn sample_wrap() -> KvWrap {
    KvWrap {
        wrap: vec![WrapItem {
            recipient_handle: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
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

fn sample_entry_value(key: &str, disclosed: bool) -> KvEntryValue {
    KvEntryValue {
        salt: encode_base64url_nopad(&[0u8; 32]),
        k: key.to_string(),
        aead: "xchacha20-poly1305".to_string(),
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        disclosed,
    }
}

fn encode_entry(val: &KvEntryValue) -> String {
    TokenCodec::encode(TokenCodec::JsonJcs, val).unwrap()
}

#[test]
fn test_kv_document_entry_preserved_accessors() {
    let e = KvDocumentEntry::Preserved {
        key: "FOO".to_string(),
        token: "tok".to_string(),
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
    let w = WrapSource::Decoded(sample_wrap());
    assert_eq!(w.data().wrap.len(), 1);
}

#[test]
fn test_wrap_source_raw_data() {
    let w = WrapSource::Raw {
        data: sample_wrap(),
        token: "raw_tok".to_string(),
    };
    assert_eq!(w.data().wrap.len(), 1);
}

#[test]
fn test_wrap_source_data_mut_promotes_raw_to_decoded() {
    let mut w = WrapSource::Raw {
        data: sample_wrap(),
        token: "raw_tok".to_string(),
    };
    let _d = w.data_mut();
    assert!(matches!(w, WrapSource::Decoded(_)));
}

#[test]
fn test_builder_new_creates_decoded_wrap() {
    let b = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false);
    let doc = b.build();
    assert!(matches!(doc.wrap, WrapSource::Decoded(_)));
    assert!(doc.entries.is_empty());
}

#[test]
fn test_builder_from_lines_with_some_wrap() {
    let wrap = sample_wrap();
    let wrap_tok = encode_wrap_token(&wrap);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V4,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap { token: wrap_tok },
        KvEncLine::KV {
            key: "A".to_string(),
            token: "ta".to_string(),
        },
    ];
    let b = KvDocumentBuilder::from_lines(
        sample_head(),
        Some(wrap.clone()),
        &lines,
        TokenCodec::JsonJcs,
        false,
    )
    .unwrap();
    let doc = b.build();
    assert!(matches!(doc.wrap, WrapSource::Decoded(_)));
    assert_eq!(doc.entries.len(), 1);
    assert_eq!(doc.entries[0].key(), "A");
}

#[test]
fn test_builder_from_lines_with_none_wrap_decodes_raw() {
    let wrap = sample_wrap();
    let wrap_tok = encode_wrap_token(&wrap);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V4,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: wrap_tok.clone(),
        },
        KvEncLine::KV {
            key: "B".to_string(),
            token: "tb".to_string(),
        },
    ];
    let b = KvDocumentBuilder::from_lines(sample_head(), None, &lines, TokenCodec::JsonJcs, false)
        .unwrap();
    let doc = b.build();
    assert!(matches!(doc.wrap, WrapSource::Raw { .. }));
    assert_eq!(doc.entries.len(), 1);
}

#[test]
fn test_builder_with_entries_appends() {
    let b = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false);
    let doc = b
        .with_entries(vec![("X".to_string(), "tx".to_string())])
        .build();
    assert_eq!(doc.entries.len(), 1);
    assert!(matches!(&doc.entries[0], KvDocumentEntry::Encoded { .. }));
}

#[test]
fn test_unsigned_doc_entry_keys() {
    let doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false)
        .with_entries(vec![
            ("A".to_string(), "ta".to_string()),
            ("B".to_string(), "tb".to_string()),
        ])
        .build();
    assert_eq!(doc.entry_keys(), vec!["A", "B"]);
}

#[test]
fn test_unsigned_doc_has_entry() {
    let doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false)
        .with_entries(vec![("K".to_string(), "t".to_string())])
        .build();
    assert!(doc.has_entry("K"));
    assert!(!doc.has_entry("X"));
}

#[test]
fn test_unsigned_doc_set_entries_replaces_and_appends() {
    let mut doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false)
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
    let mut doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false)
        .with_entries(vec![
            ("A".to_string(), "ta".to_string()),
            ("B".to_string(), "tb".to_string()),
        ])
        .build();
    doc.unset_entry("A");
    assert_eq!(doc.entry_keys(), vec!["B"]);
}

#[test]
fn test_unsigned_doc_update_timestamp() {
    let mut doc =
        KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false).build();
    let old = doc.head().updated_at.clone();
    doc.update_timestamp().unwrap();
    assert_ne!(doc.head().updated_at, old);
}

#[test]
fn test_unsigned_doc_wrap_mut_promotes() {
    let wrap = sample_wrap();
    let wrap_tok = encode_wrap_token(&wrap);
    let lines = vec![
        KvEncLine::Header {
            version: KvEncVersion::V4,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: wrap_tok.clone(),
        },
    ];
    let mut doc =
        KvDocumentBuilder::from_lines(sample_head(), None, &lines, TokenCodec::JsonJcs, false)
            .unwrap()
            .build();

    assert!(matches!(doc.wrap, WrapSource::Raw { .. }));
    let _w = doc.wrap_mut();
    assert!(matches!(doc.wrap, WrapSource::Decoded(_)));
}

#[test]
fn test_serialize_unsigned_format() {
    let val_a = sample_entry_value("A", false);
    let val_b = sample_entry_value("B", false);
    let doc = KvDocumentBuilder::new(sample_head(), sample_wrap(), TokenCodec::JsonJcs, false)
        .with_entries(vec![
            ("A".to_string(), encode_entry(&val_a)),
            ("B".to_string(), encode_entry(&val_b)),
        ])
        .build();

    let s = doc.serialize_unsigned().unwrap();
    assert!(s.starts_with(":SECRETENV_KV 4\n"));
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
            version: KvEncVersion::V4,
        },
        KvEncLine::Head {
            token: "ht".to_string(),
        },
        KvEncLine::Wrap {
            token: wrap_tok.clone(),
        },
    ];
    let doc =
        KvDocumentBuilder::from_lines(sample_head(), None, &lines, TokenCodec::JsonJcs, false)
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
            version: KvEncVersion::V4,
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

    let mut doc = KvDocumentBuilder::from_lines(
        sample_head(),
        Some(sample_wrap()),
        &lines,
        TokenCodec::JsonJcs,
        false,
    )
    .unwrap()
    .build();

    doc.clear_disclosed_flags().unwrap();

    assert!(matches!(&doc.entries[0], KvDocumentEntry::Encoded { .. }));
    let decoded_a: KvEntryValue = parse_kv_entry_token(doc.entries[0].token()).unwrap();
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
            version: KvEncVersion::V4,
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

    let mut doc = KvDocumentBuilder::from_lines(
        sample_head(),
        Some(sample_wrap()),
        &lines,
        TokenCodec::JsonJcs,
        false,
    )
    .unwrap()
    .build();

    doc.clear_disclosed_flags().unwrap();
    assert!(matches!(&doc.entries[0], KvDocumentEntry::Preserved { .. }));
}
