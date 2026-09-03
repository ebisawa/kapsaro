// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for CLI-local presentation and input validation helpers.

use super::{format_kid_display, format_kid_display_lossy, validate_github_login};

#[test]
fn kid_display_groups_the_canonical_identifier() {
    let display =
        format_kid_display("0123456789abcdefghjkmnpqrstvwxyz").expect("valid KID should format");

    assert_eq!(display, "0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ");
}

#[test]
fn lossy_kid_display_escapes_control_characters() {
    assert_eq!(format_kid_display_lossy("bad\nKID"), "bad\\nKID");
}

#[test]
fn github_login_validation_accepts_single_hyphens() {
    validate_github_login("alice-example").expect("valid GitHub login");
}

#[test]
fn github_login_validation_rejects_consecutive_hyphens() {
    assert!(validate_github_login("alice--example").is_err());
}
