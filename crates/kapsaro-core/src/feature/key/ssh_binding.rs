// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH-backed key generation binding context.

use crate::io::ssh::backend::SignatureBackend;
use crate::model::ssh::SshDeterminismStatus;

pub struct SshBindingContext {
    pub public_key: String,
    pub fingerprint: String,
    pub backend: Box<dyn SignatureBackend>,
    pub determinism: SshDeterminismStatus,
}
