// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH signing service types and explicit runtime input resolution.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::io::ssh::backend::{build_backend, SignatureBackend as InternalSignatureBackend};
use crate::io::ssh::external::add::DefaultSshAdd;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::external::pubkey::{
    load_ed25519_keys_from_agent, load_ssh_key_candidate_from_file, SshKeyCandidate,
};
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::protocol::SshKeyDescriptor;
use crate::model::wire::context::SSHSIG_MESSAGE_DETERMINISM_CHECK_V1;
use crate::{Error, Result};

pub use crate::config::types::SshSigningMethod;
pub use crate::model::ssh::SshDeterminismStatus;

/// CLI-resolved inputs for locating and using an SSH signing key.
#[derive(Debug, Clone)]
pub struct SshSigningInputs {
    method: SshSigningMethod,
    identity: Option<PathBuf>,
    agent_socket: Option<PathBuf>,
    ssh_keygen_command: String,
    ssh_add_command: String,
}

/// Public details of one SSH key available to the resolved signing method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyCandidateView {
    pub public_key: String,
    pub fingerprint: String,
    pub comment: String,
}

/// SSH context selected from explicit inputs and ready for key generation.
pub struct SshSigningContextResolution {
    pub public_key: String,
    pub fingerprint: String,
    pub backend: Box<dyn InternalSignatureBackend>,
    pub determinism: SshDeterminismStatus,
}

pub(crate) struct ResolvedSshSigningContext {
    pub(crate) public_key: String,
    pub(crate) backend: Box<dyn InternalSignatureBackend>,
}

/// SSHSIG-compatible Ed25519 raw signature returned by caller-supplied backends.
#[derive(Clone, PartialEq, Eq)]
pub struct SshRawSignature {
    inner: Ed25519RawSignature,
}

/// Caller-supplied SSH signing backend for facade APIs.
pub trait SshSignatureBackend {
    /// Sign message bytes in a specific SSHSIG namespace.
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<SshRawSignature>;
}

impl SshRawSignature {
    /// Build a raw signature from exactly 64 bytes.
    pub fn new(bytes: [u8; 64]) -> Self {
        Self {
            inner: Ed25519RawSignature::new(bytes),
        }
    }

    /// Return the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        self.inner.as_bytes()
    }

    pub(crate) fn into_internal(self) -> Ed25519RawSignature {
        self.inner
    }
}

impl SshSigningInputs {
    /// Build SSH inputs after CLI, environment, and configuration resolution.
    pub fn new(
        method: SshSigningMethod,
        identity: Option<PathBuf>,
        agent_socket: Option<PathBuf>,
        ssh_keygen_command: impl Into<String>,
        ssh_add_command: impl Into<String>,
    ) -> Self {
        Self {
            method,
            identity,
            agent_socket,
            ssh_keygen_command: ssh_keygen_command.into(),
            ssh_add_command: ssh_add_command.into(),
        }
    }
}

/// Resolve an agent socket from a caller-fixed home and environment snapshot.
pub fn resolve_ssh_agent_socket(
    home: Option<&Path>,
    ssh_auth_sock: Option<PathBuf>,
    expansion_values: &BTreeMap<String, String>,
) -> Result<Option<PathBuf>> {
    crate::io::ssh::agent::socket::resolve_agent_socket_path(home, ssh_auth_sock, expansion_values)
}

impl SshSigningContextResolution {
    pub(crate) fn into_ssh_binding(self) -> crate::feature::key::ssh_binding::SshBindingContext {
        crate::feature::key::ssh_binding::SshBindingContext {
            public_key: self.public_key,
            fingerprint: self.fingerprint,
            backend: self.backend,
            determinism: self.determinism,
        }
    }
}

/// List SSH keys using only caller-resolved paths and method selection.
pub fn resolve_ssh_key_candidates(inputs: &SshSigningInputs) -> Result<Vec<SshKeyCandidateView>> {
    load_candidates(inputs).map(|candidates| {
        candidates
            .into_iter()
            .map(|candidate| SshKeyCandidateView {
                public_key: candidate.public_key,
                fingerprint: candidate.fingerprint,
                comment: candidate.comment,
            })
            .collect()
    })
}

/// Build a signing context from a key returned by candidate resolution.
pub fn build_ssh_signing_context(
    inputs: &SshSigningInputs,
    selected_public_key: &str,
    check_determinism: bool,
) -> Result<SshSigningContextResolution> {
    validate_ed25519_key(selected_public_key)?;
    let fingerprint = crate::io::ssh::protocol::build_sha256_fingerprint(selected_public_key)?;
    let backend = build_resolved_backend(inputs)?;
    let determinism =
        check_determinism_status(check_determinism, backend.as_ref(), selected_public_key)?;
    Ok(SshSigningContextResolution {
        public_key: selected_public_key.to_string(),
        fingerprint,
        backend,
        determinism,
    })
}

pub(crate) fn resolve_ssh_signing_context(
    inputs: &SshSigningInputs,
    expected_fingerprint: &str,
) -> Result<ResolvedSshSigningContext> {
    let resolved =
        resolve_ssh_signing_context_for_fingerprint(inputs, expected_fingerprint, false)?;
    Ok(ResolvedSshSigningContext {
        public_key: resolved.public_key,
        backend: resolved.backend,
    })
}

pub(crate) fn resolve_ssh_signing_context_for_fingerprint(
    inputs: &SshSigningInputs,
    expected_fingerprint: &str,
    check_determinism: bool,
) -> Result<SshSigningContextResolution> {
    let candidates = load_candidates(inputs)?;
    let selected = candidates
        .into_iter()
        .find(|candidate| candidate.fingerprint == expected_fingerprint)
        .ok_or_else(|| missing_selected_key(expected_fingerprint))?;
    build_ssh_signing_context(inputs, &selected.public_key, check_determinism)
}

fn load_candidates(inputs: &SshSigningInputs) -> Result<Vec<SshKeyCandidate>> {
    let ssh_keygen = DefaultSshKeygen::new(
        inputs.ssh_keygen_command.clone(),
        inputs.agent_socket.clone(),
    );
    match (inputs.method, inputs.identity.as_ref()) {
        (SshSigningMethod::SshKeygen, Some(path)) | (SshSigningMethod::SshAgent, Some(path)) => {
            let descriptor = SshKeyDescriptor::from_path(path.clone());
            load_ssh_key_candidate_from_file(&ssh_keygen, &descriptor)
                .map(|candidate| vec![candidate])
        }
        (SshSigningMethod::SshAgent, None) => load_ed25519_keys_from_agent(&DefaultSshAdd::new(
            inputs.ssh_add_command.clone(),
            inputs.agent_socket.clone(),
        )),
        (SshSigningMethod::SshKeygen, None) => Err(Error::build_config_error(
            "SSH identity is required for ssh-keygen signing".to_string(),
        )),
    }
}

fn backend_descriptor(inputs: &SshSigningInputs) -> Result<Option<SshKeyDescriptor>> {
    match inputs.method {
        SshSigningMethod::SshAgent => Ok(None),
        SshSigningMethod::SshKeygen => inputs
            .identity
            .clone()
            .map(SshKeyDescriptor::from_path)
            .map(Some)
            .ok_or_else(|| {
                Error::build_config_error(
                    "SSH identity is required for ssh-keygen signing".to_string(),
                )
            }),
    }
}

fn build_resolved_backend(inputs: &SshSigningInputs) -> Result<Box<dyn InternalSignatureBackend>> {
    build_backend(
        inputs.method,
        Box::new(DefaultSshKeygen::new(
            inputs.ssh_keygen_command.clone(),
            inputs.agent_socket.clone(),
        )),
        backend_descriptor(inputs)?,
        inputs.agent_socket.clone(),
    )
}

fn check_determinism_status(
    enabled: bool,
    backend: &dyn InternalSignatureBackend,
    public_key: &str,
) -> Result<SshDeterminismStatus> {
    if !enabled {
        return Ok(SshDeterminismStatus::Skipped);
    }
    match backend.check_sshsig_determinism(
        crate::io::ssh::protocol::constants::KEY_PROTECTION_NAMESPACE,
        public_key,
        SSHSIG_MESSAGE_DETERMINISM_CHECK_V1,
    ) {
        Ok(()) => Ok(SshDeterminismStatus::Verified),
        Err(error) if is_non_deterministic_signature_error(&error) => {
            Ok(SshDeterminismStatus::Failed {
                message: concat!(
                    "SSH signature determinism check failed.\n",
                    "A deterministic SSH key is required for key generation."
                )
                .to_string(),
            })
        }
        Err(error) => Err(error),
    }
}

fn is_non_deterministic_signature_error(error: &Error) -> bool {
    error
        .to_string()
        .contains("Non-deterministic signature detected: same input produced different signatures")
}

fn validate_ed25519_key(public_key: &str) -> Result<()> {
    if public_key.split_whitespace().next() == Some("ssh-ed25519") {
        return Ok(());
    }
    Err(Error::build_invalid_argument_error(format!(
        "Only Ed25519 SSH keys are supported. Got: {}",
        public_key.split_whitespace().next().unwrap_or("unknown")
    )))
}

fn missing_selected_key(fingerprint: &str) -> Error {
    Error::build_not_found_error(format!(
        "SSH key for the selected key ({fingerprint}) not found in ssh-agent. \
         Load it with ssh-add or specify with -i"
    ))
}

impl std::fmt::Debug for SshRawSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshRawSignature([REDACTED])")
    }
}

pub(crate) fn into_internal_backend(
    backend: Box<dyn SshSignatureBackend>,
) -> Box<dyn InternalSignatureBackend> {
    Box::new(SshSignatureBackendAdapter { backend })
}

struct SshSignatureBackendAdapter {
    backend: Box<dyn SshSignatureBackend>,
}

impl InternalSignatureBackend for SshSignatureBackendAdapter {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature> {
        self.backend
            .sign_sshsig(namespace, ssh_pubkey, message)
            .map(SshRawSignature::into_internal)
    }
}
