// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

mod candidate;
mod determinism;
mod resolution;

use crate::app::context::member::resolve_command_member;
use crate::app::context::options::CommonCommandOptions;
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::storage::load_private_key;
use crate::io::ssh::backend::{build_backend, SignatureBackend};
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::external::pubkey::SshKeyCandidate;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::model::private_key::PrivateKey;
use crate::model::private_key::PrivateKeyAlgorithm;
use crate::model::ssh::SshDeterminismStatus;
use crate::{Error, Result};
use candidate::resolve_ssh_key_candidates as resolve_app_ssh_key_candidates;
use determinism::{check_ssh_signature_determinism, validate_ssh_key_type};
use resolution::{resolve_backend_key_descriptor, resolve_signing_method, resolve_ssh_commands};
use tracing::debug;

pub struct SshSigningContextResolution {
    pub public_key: String,
    pub fingerprint: String,
    pub backend: Box<dyn SignatureBackend>,
    pub determinism: SshDeterminismStatus,
}

impl SshSigningContextResolution {
    pub fn into_ssh_binding(self) -> SshBindingContext {
        SshBindingContext {
            public_key: self.public_key,
            fingerprint: self.fingerprint,
            backend: self.backend,
            determinism: self.determinism,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyCandidateView {
    pub public_key: String,
    pub fingerprint: String,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub struct SshSigningParams {
    pub ssh_key: Option<PathBuf>,
    pub signing_method: Option<crate::config::types::SshSigningMethod>,
    pub base_dir: Option<PathBuf>,
    pub verbose: bool,
    pub check_determinism: bool,
}

fn build_ssh_signing_params(options: &CommonCommandOptions) -> SshSigningParams {
    SshSigningParams {
        ssh_key: options.identity.clone(),
        signing_method: options.ssh_signing_method,
        base_dir: options.home.clone(),
        verbose: options.debug,
        check_determinism: false,
    }
}

pub fn resolve_ssh_key_candidates(
    options: &CommonCommandOptions,
) -> Result<Vec<SshKeyCandidateView>> {
    let params = build_ssh_signing_params(options);
    resolve_ssh_key_candidates_with_params(&params)
}

pub fn resolve_ssh_key_candidates_with_params(
    params: &SshSigningParams,
) -> Result<Vec<SshKeyCandidateView>> {
    let candidates = resolve_app_ssh_key_candidates(params)?;
    if params.verbose {
        debug!("[SSH] candidate count={}", candidates.len());
    }
    Ok(build_ssh_candidate_views(candidates))
}

pub fn build_ssh_signing_context(
    options: &CommonCommandOptions,
    selected_pubkey: &str,
    check_determinism: bool,
) -> Result<SshSigningContextResolution> {
    let mut params = build_ssh_signing_params(options);
    params.check_determinism = check_determinism;
    build_ssh_signing_context_with_params(&params, selected_pubkey)
}

pub fn build_ssh_signing_context_with_params(
    params: &SshSigningParams,
    selected_pubkey: &str,
) -> Result<SshSigningContextResolution> {
    let ssh_signing_context = build_app_ssh_signing_context(params, selected_pubkey)?;
    if params.verbose {
        debug!(
            "[SSH] signing context: fingerprint={}, determinism={}",
            ssh_signing_context.fingerprint,
            format_determinism(&ssh_signing_context.determinism)
        );
    }
    Ok(SshSigningContextResolution {
        public_key: ssh_signing_context.public_key,
        fingerprint: ssh_signing_context.fingerprint,
        backend: ssh_signing_context.backend,
        determinism: ssh_signing_context.determinism,
    })
}

fn build_app_ssh_signing_context(
    params: &SshSigningParams,
    selected_pubkey: &str,
) -> Result<SshSigningContextResolution> {
    let base_dir = params.base_dir.as_deref();
    let signing_method = resolve_signing_method(params, base_dir)?;
    let commands = resolve_ssh_commands(base_dir)?;

    validate_ssh_key_type(selected_pubkey)?;
    let fingerprint = build_sha256_fingerprint(selected_pubkey)?;
    let key_descriptor = resolve_backend_key_descriptor(signing_method, &params.ssh_key, base_dir)?;

    let ssh_keygen = Box::new(DefaultSshKeygen::new(commands.ssh_keygen_path));
    let backend = build_backend(signing_method, ssh_keygen, key_descriptor)?;
    let determinism = check_ssh_signature_determinism(params, backend.as_ref(), selected_pubkey)?;

    Ok(SshSigningContextResolution {
        public_key: selected_pubkey.to_string(),
        fingerprint,
        backend,
        determinism,
    })
}

pub fn resolve_ssh_context_by_active_key(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
) -> Result<SshSigningContextResolution> {
    let resolved = resolve_command_member(options, member_handle)?;
    let fingerprint =
        resolve_active_key_ssh_fingerprint(&resolved.member_handle, &resolved.paths.keystore_root)?;
    resolve_ssh_context_for_fingerprint(options, &fingerprint)
}

pub fn find_ssh_candidate_by_fingerprint<'a>(
    candidates: &'a [SshKeyCandidateView],
    fingerprint: &str,
) -> Result<&'a SshKeyCandidateView> {
    candidates
        .iter()
        .find(|candidate| candidate.fingerprint == fingerprint)
        .ok_or_else(|| {
            Error::build_not_found_error(format!(
                "SSH key for active key ({fingerprint}) not found in ssh-agent. \
                 Load it with ssh-add or specify with -i"
            ))
        })
}

fn build_ssh_candidate_views(candidates: Vec<SshKeyCandidate>) -> Vec<SshKeyCandidateView> {
    candidates
        .into_iter()
        .map(|candidate| SshKeyCandidateView {
            public_key: candidate.public_key,
            fingerprint: candidate.fingerprint,
            comment: candidate.comment,
        })
        .collect()
}

fn resolve_ssh_context_for_fingerprint(
    options: &CommonCommandOptions,
    fingerprint: &str,
) -> Result<SshSigningContextResolution> {
    let candidates = resolve_ssh_key_candidates(options)?;
    let matched = find_ssh_candidate_by_fingerprint(&candidates, fingerprint)?;
    if options.debug {
        debug!("[SSH] matched active key fingerprint={}", fingerprint);
    }
    build_ssh_signing_context(options, &matched.public_key, false)
}

fn resolve_active_key_ssh_fingerprint(
    member_handle: &str,
    keystore_root: &std::path::Path,
) -> Result<String> {
    let kid = load_active_kid_for_ssh_context(member_handle, keystore_root)?;
    let private_key = load_private_key(keystore_root, member_handle, &kid)?;
    Ok(resolve_ssh_fingerprint_from_private_key(&private_key)?.to_string())
}

fn format_determinism(status: &SshDeterminismStatus) -> &str {
    match status {
        SshDeterminismStatus::Verified => "verified",
        SshDeterminismStatus::Skipped => "skipped",
        SshDeterminismStatus::Failed { .. } => "failed",
    }
}

fn load_active_kid_for_ssh_context(
    member_handle: &str,
    keystore_root: &std::path::Path,
) -> Result<String> {
    load_active_kid(member_handle, keystore_root)?.ok_or_else(|| {
        Error::build_not_found_error(format!("No active key for member: {}", member_handle))
    })
}

fn resolve_ssh_fingerprint_from_private_key(private_key: &PrivateKey) -> Result<&str> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => Ok(fpr.as_str()),
        _ => Err(Error::build_crypto_error(
            "Expected SshSig algorithm for SSH signing context".to_string(),
        )),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_ssh_member_handle_test.rs"]
mod app_context_ssh_member_handle_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_ssh_match_test.rs"]
mod feature_context_ssh_match_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_ssh_test.rs"]
mod feature_context_ssh_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_verify_public_key_attestation_test.rs"]
mod feature_verify_public_key_attestation_test;
