// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature backend abstraction
//!
//! Provides a unified interface for obtaining SSH signatures via two methods:
//! - Method A: ssh-agent protocol (direct)
//! - Method B: ssh-keygen subprocess (with SSHSIG parsing)

pub mod factory;
pub mod signature_backend;
pub mod ssh_agent;
pub mod ssh_keygen;

pub use factory::build_backend;
pub use signature_backend::SignatureBackend;
