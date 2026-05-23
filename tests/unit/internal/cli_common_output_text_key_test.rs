// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::display_kid_or_raw;

#[test]
fn test_display_kid_or_raw_formats_valid_kid() {
    assert_eq!(
        display_kid_or_raw("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"
    );
}

#[test]
fn test_display_kid_or_raw_keeps_invalid_kid() {
    assert_eq!(display_kid_or_raw("not-a-kid"), "not-a-kid");
}
