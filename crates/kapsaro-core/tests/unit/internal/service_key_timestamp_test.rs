// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for resolving key timestamps against the current clock.
//! Covers what the pair of RFC3339 strings says, and that an expiry just resolved is accepted
//! by the check that runs immediately before the key is written.

use super::{ensure_expiry_not_reached, resolve_key_timestamps};

fn valid_for(duration: &str) -> Option<String> {
    Some(duration.to_string())
}

fn parse_rfc3339(timestamp: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).unwrap()
}

/// Both timestamps are emitted as RFC3339 text, and the expiry is measured from
/// the creation time recorded beside it rather than from a second clock
/// reading. Parsing the pair back and taking the span between them states both.
#[test]
fn test_resolve_key_timestamps_roundtrip() {
    let (created_at, expires_at) = resolve_key_timestamps(&None, &valid_for("30d")).unwrap();

    assert_eq!(
        parse_rfc3339(&expires_at) - parse_rfc3339(&created_at),
        time::Duration::days(30)
    );
}

/// An expiry still ahead of the moment the key is stored is what the keystore
/// accepts, so the check that runs just before the write accepts it too.
#[test]
fn test_a_resolved_expiry_is_still_ahead_when_the_key_is_stored() {
    let (_created_at, expires_at) = resolve_key_timestamps(&None, &valid_for("30d")).unwrap();

    assert!(ensure_expiry_not_reached(&expires_at).is_ok());
}
