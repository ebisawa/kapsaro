// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH protocol primitives (pure functions).

pub mod base64;
pub mod constants;
pub mod fingerprint;
pub mod key_descriptor;
pub mod parse;
pub mod sshsig;
pub mod types;
pub mod wire;

pub use fingerprint::build_sha256_fingerprint;
pub use key_descriptor::SshKeyDescriptor;
