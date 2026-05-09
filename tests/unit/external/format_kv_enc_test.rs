// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc format parser tests.
//!
//! Tests for line-oriented kv-enc format parsing.

use secretenv::format::kv::enc::parser::KvEncParser;
use secretenv::model::kv_enc::line::{KvEncLine, KvEncVersion};

// Header parsing tests

#[test]
fn test_parse_header_v6() {
    let parsed = KvEncParser::parse_line(":SECRETENV_KV 6").unwrap();
    assert_eq!(
        parsed,
        KvEncLine::Header {
            version: KvEncVersion::V6
        }
    );
}

#[test]
fn test_parse_header_v2_rejected() {
    // v2 should be rejected with an error
    let result = KvEncParser::parse_line(":SECRETENV_KV 2");
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(
            e.to_string().contains("Unsupported kv-enc version")
                || e.to_string().contains("only v6 is supported")
        );
    }
}

#[test]
fn test_parse_header_invalid_version() {
    assert!(KvEncParser::parse_line(":SECRETENV_KV 1").is_err());
    assert!(KvEncParser::parse_line(":SECRETENV_KV 4").is_err());
}

#[test]
fn test_parse_header_old_format_rejected() {
    // Old format (:SECRETV_KV 3) should be rejected (strict mode)
    let result = KvEncParser::parse_line(":SECRETV_KV 3");
    assert!(result.is_err(), "Old header format should be rejected");
}

#[test]
fn test_parse_header_without_colon_as_kv() {
    // Format without : prefix is parsed as KV line (not as header)
    // This is expected behavior - format detection will reject it, not the parser
    let KvEncLine::KV { key, token } = KvEncParser::parse_line("SECRETENV_KV 4").unwrap() else {
        panic!("Expected KV line for format without colon");
    };
    assert_eq!(key, "SECRETENV_KV");
    assert_eq!(token, "4");
}

// Line type parsing tests

#[test]
fn test_parse_head_line() {
    let KvEncLine::Head { token } = KvEncParser::parse_line(
        ":HEAD eyJzaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTU1In0",
    )
    .unwrap() else {
        panic!("Expected Head line");
    };
    assert_eq!(
        token,
        "eyJzaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTU1In0"
    );
}

#[test]
fn test_parse_kv_line() {
    let KvEncLine::KV { key, token } =
        KvEncParser::parse_line("DATABASE_URL eyJrZXkiOiJ2YWx1ZSJ9").unwrap()
    else {
        panic!("Expected KV line");
    };
    assert_eq!(key, "DATABASE_URL");
    assert_eq!(token, "eyJrZXkiOiJ2YWx1ZSJ9");
}

#[test]
fn test_parse_wrap_line() {
    let KvEncLine::Wrap { token } = KvEncParser::parse_line(":WRAP eyJ3cmFwIjpbXX0").unwrap()
    else {
        panic!("Expected Wrap line");
    };
    assert_eq!(token, "eyJ3cmFwIjpbXX0");
}

#[test]
fn test_parse_sig_line() {
    let KvEncLine::Sig { token } =
        KvEncParser::parse_line(":SIG eyJzaWduYXR1cmUiOiIuLi4ifQ").unwrap()
    else {
        panic!("Expected Sig line");
    };
    assert_eq!(token, "eyJzaWduYXR1cmUiOiIuLi4ifQ");
}

#[test]
fn test_parse_empty_line() {
    assert_eq!(KvEncParser::parse_line("").unwrap(), KvEncLine::Empty);
}

#[test]
fn test_parse_comment_line_rejected() {
    // Comment lines are not allowed in kv-enc v6
    let result = KvEncParser::parse_line("# This is a comment");
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(
            e.to_string().contains("comment lines are not allowed")
                || e.to_string().contains("kv-enc v6")
        );
    }
}

#[test]
fn test_parse_missing_space_error() {
    assert!(KvEncParser::parse_line("DATABASE_URLeyJrZXkiOiJ2YWx1ZSJ9").is_err());
}

// Tab delimiter rejection tests

#[test]
fn test_parse_head_line_with_tab_rejected() {
    // Tab delimiter should be rejected (space required)
    let result = KvEncParser::parse_line(
        ":HEAD\teyJzaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTU1In0",
    );
    assert!(
        result.is_err(),
        "Tab delimiter in :HEAD line should be rejected"
    );
}

#[test]
fn test_parse_wrap_line_with_tab_rejected() {
    // Tab delimiter should be rejected (space required)
    let result = KvEncParser::parse_line(":WRAP\teyJ3cmFwIjpbXX0");
    assert!(
        result.is_err(),
        "Tab delimiter in :WRAP line should be rejected"
    );
}

#[test]
fn test_parse_sig_line_with_tab_rejected() {
    // Tab delimiter should be rejected (space required)
    let result = KvEncParser::parse_line(":SIG\teyJzaWduYXR1cmUiOiIuLi4ifQ");
    assert!(
        result.is_err(),
        "Tab delimiter in :SIG line should be rejected"
    );
}

#[test]
fn test_parse_kv_line_with_tab_rejected() {
    // Tab delimiter should be rejected (space required)
    // Parser uses find(' ') which won't find tab, so it will fail
    let result = KvEncParser::parse_line("DATABASE_URL\teyJrZXkiOiJ2YWx1ZSJ9");
    assert!(
        result.is_err(),
        "Tab delimiter in KV line should be rejected"
    );
}

// Full document parsing tests

#[test]
fn test_parse_document() {
    let content = ":SECRETENV_KV 6\n\
                   :HEAD eyJzaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTU1In0\n\
                   :WRAP eyJ3cmFwIjpbXX0\n\
                   DATABASE_URL eyJzYWx0IjoiQUFBQUFBQUFBQUFBQUFBQSIsImsiOiJEQVRBQkFTRV9VUkwifQ\n\
                   API_KEY eyJzYWx0IjoiQkJCQkJCQkJCQkJCQkJCQiIsImsiOiJBUElfS0VZIn0\n\
                   :SIG eyJzaWciOiIuLi4ifQ";

    let lines = KvEncParser::new(content).parse_all().unwrap();

    assert_eq!(lines.len(), 6);
    assert!(matches!(
        lines[0],
        KvEncLine::Header {
            version: KvEncVersion::V6
        }
    ));
    assert!(matches!(lines[1], KvEncLine::Head { .. }));
    assert!(matches!(lines[2], KvEncLine::Wrap { .. }));
    assert!(matches!(lines[3], KvEncLine::KV { .. }));
    assert!(matches!(lines[4], KvEncLine::KV { .. }));
    assert!(matches!(lines[5], KvEncLine::Sig { .. }));
}

#[test]
fn test_parse_with_empty_lines() {
    // Empty lines are allowed
    let content = ":SECRETENV_KV 6\n:HEAD token0\n:WRAP token\n\nDATABASE_URL token2";

    let lines = KvEncParser::new(content).parse_all().unwrap();

    assert_eq!(lines.len(), 5);
    assert!(matches!(lines[0], KvEncLine::Header { .. }));
    assert!(matches!(lines[1], KvEncLine::Head { .. }));
    assert!(matches!(lines[2], KvEncLine::Wrap { .. }));
    assert!(matches!(lines[3], KvEncLine::Empty));
    assert!(matches!(lines[4], KvEncLine::KV { .. }));
}

#[test]
fn test_parse_with_comment_rejected() {
    // Comment lines are not allowed in kv-enc v6
    let content = ":SECRETENV_KV 6\n:HEAD token0\n:WRAP token\n# Comment\nDATABASE_URL token2";

    let result = KvEncParser::new(content).parse_all();
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(
            e.to_string().contains("comment lines are not allowed")
                || e.to_string().contains("kv-enc v6")
        );
    }
}

// Diff-friendly roundtrip test

#[test]
fn test_kv_line_roundtrip_preservation() {
    let original = "DATABASE_URL eyJvcmlnaW5hbCI6InRydWUifQ";
    let KvEncLine::KV { key, token } = KvEncParser::parse_line(original).unwrap() else {
        panic!("Expected KV line");
    };

    let serialized = format!("{key} {token}");
    assert_eq!(serialized, original);
}
