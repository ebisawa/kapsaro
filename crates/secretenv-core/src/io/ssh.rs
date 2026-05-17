// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH integration: signature backends, ssh-agent communication, SSHSIG verification.

pub mod agent;
pub mod backend;
pub mod error;
pub mod external;
pub mod openssh_config;
pub mod protocol;
pub mod verify;

pub use error::SshError;
