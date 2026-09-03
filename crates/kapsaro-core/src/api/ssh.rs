// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public SSH signing API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::ssh::{
    build_ssh_signing_context, resolve_ssh_agent_socket, resolve_ssh_key_candidates,
    SshDeterminismStatus, SshKeyCandidateView, SshRawSignature, SshSignatureBackend,
    SshSigningContextResolution, SshSigningInputs, SshSigningMethod,
};
