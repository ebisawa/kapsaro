// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient public key source boundary tests.
//! Covers rejecting every invalid member handle before any key source I/O runs.

use super::verify_recipient_public_keys_from_source;
use crate::io::keystore::public_key_source::PublicKeySource;
use crate::model::identity::MemberHandle;
use crate::model::public_key::PublicKey;
use crate::Result;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
struct TrackingPublicKeySource {
    called: AtomicBool,
}

impl PublicKeySource for TrackingPublicKeySource {
    fn load_public_key(&self, _member_handle: &MemberHandle) -> Result<PublicKey> {
        self.called.store(true, Ordering::SeqCst);
        unreachable!("invalid member handles must be rejected before I/O")
    }

    fn load_public_keys_for_member_handles(
        &self,
        _member_handles: &[MemberHandle],
    ) -> Result<Vec<PublicKey>> {
        self.called.store(true, Ordering::SeqCst);
        unreachable!("invalid member handles must be rejected before I/O")
    }
}

#[test]
fn test_verify_recipients_validates_all_member_handles_before_io() {
    let source = TrackingPublicKeySource::default();
    let handles = vec!["alice@example.com".to_string(), "../outside".to_string()];

    assert!(verify_recipient_public_keys_from_source(&source, &handles).is_err());
    assert!(!source.called.load(Ordering::SeqCst));
}
