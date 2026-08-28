// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH signing environment resolution for commands.
//! Selects the identity and signing method the local key will be unlocked with.

use std::path::PathBuf;

mod candidate;
mod determinism;
mod resolution;

use crate::app::context::member::{resolve_command_member, CommandMemberResolution};
use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::ssh::backend::{build_backend, SignatureBackend};
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::external::pubkey::SshKeyCandidate;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::model::identity::{Kid, MemberHandle};
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

/// SSH context bound to the canonical KID selected from the keystore.
pub(crate) struct SshSigningKeyResolution {
    pub(crate) kid: Kid,
    pub(crate) context: SshSigningContextResolution,
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
    #[cfg(test)]
    pub base_dir: Option<PathBuf>,
    pub check_determinism: bool,
}

impl SshSigningParams {
    /// The configuration this signing environment resolves its settings from.
    ///
    /// The signing method, both external commands and the key path are all
    /// configured in one file, so one snapshot answers for all of them.
    #[cfg(test)]
    fn global_config(&self) -> GlobalConfigSnapshot {
        GlobalConfigSnapshot::for_base_dir(self.base_dir.as_deref())
    }
}

fn build_ssh_signing_params(options: &CommonCommandOptions) -> SshSigningParams {
    SshSigningParams {
        ssh_key: options.identity.clone(),
        signing_method: options.ssh_signing_method,
        #[cfg(test)]
        base_dir: options.home.clone(),
        check_determinism: false,
    }
}

pub fn resolve_ssh_key_candidates(
    options: &CommonCommandOptions,
) -> Result<Vec<SshKeyCandidateView>> {
    let params = build_ssh_signing_params(options);
    resolve_ssh_key_candidates_with_config(&params, options.global_config()?)
}

#[cfg(test)]
pub fn resolve_ssh_key_candidates_with_params(
    params: &SshSigningParams,
) -> Result<Vec<SshKeyCandidateView>> {
    resolve_ssh_key_candidates_with_config(params, &params.global_config())
}

fn resolve_ssh_key_candidates_with_config(
    params: &SshSigningParams,
    config: &GlobalConfigSnapshot,
) -> Result<Vec<SshKeyCandidateView>> {
    let candidates = resolve_app_ssh_key_candidates(params, config)?;
    debug!("[SSH] candidate count={}", candidates.len());
    Ok(build_ssh_candidate_views(candidates))
}

pub fn build_ssh_signing_context(
    options: &CommonCommandOptions,
    selected_pubkey: &str,
    check_determinism: bool,
) -> Result<SshSigningContextResolution> {
    let mut params = build_ssh_signing_params(options);
    params.check_determinism = check_determinism;
    build_ssh_signing_context_with_config(&params, options.global_config()?, selected_pubkey)
}

#[cfg(test)]
pub fn build_ssh_signing_context_with_params(
    params: &SshSigningParams,
    selected_pubkey: &str,
) -> Result<SshSigningContextResolution> {
    build_ssh_signing_context_with_config(params, &params.global_config(), selected_pubkey)
}

fn build_ssh_signing_context_with_config(
    params: &SshSigningParams,
    config: &GlobalConfigSnapshot,
    selected_pubkey: &str,
) -> Result<SshSigningContextResolution> {
    let ssh_signing_context = build_app_ssh_signing_context(params, config, selected_pubkey)?;
    debug!(
        "[SSH] signing context: fingerprint={}, determinism={}",
        ssh_signing_context.fingerprint,
        format_determinism(&ssh_signing_context.determinism)
    );
    Ok(SshSigningContextResolution {
        public_key: ssh_signing_context.public_key,
        fingerprint: ssh_signing_context.fingerprint,
        backend: ssh_signing_context.backend,
        determinism: ssh_signing_context.determinism,
    })
}

fn build_app_ssh_signing_context(
    params: &SshSigningParams,
    config: &GlobalConfigSnapshot,
    selected_pubkey: &str,
) -> Result<SshSigningContextResolution> {
    let signing_method = resolve_signing_method(params, config)?;
    let commands = resolve_ssh_commands(config)?;

    validate_ssh_key_type(selected_pubkey)?;
    let fingerprint = build_sha256_fingerprint(selected_pubkey)?;
    let key_descriptor = resolve_backend_key_descriptor(signing_method, &params.ssh_key, config)?;

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

/// Choose the SSH key that backs one key of a member.
///
/// `explicit_kid` names the key the caller asked for, and the SSH identity is
/// chosen for that key rather than for whichever one is active; a caller that
/// names none falls back to the active key. For a command that goes on to load
/// the signing key, resolve the member first and use
/// [`resolve_ssh_context_for_resolved_member`] instead: resolving twice lets a
/// rotation land between the two reads.
pub fn resolve_ssh_context_for_member_key(
    options: &CommonCommandOptions,
    member_handle: Option<String>,
    explicit_kid: Option<&str>,
) -> Result<SshSigningContextResolution> {
    let resolved = resolve_command_member(options, member_handle)?;
    resolve_ssh_context_for_resolved_member(options, &resolved, explicit_kid)
        .map(|resolution| resolution.context)
}

/// Choose the SSH key that backs one key of an already resolved member.
///
/// The resolution is borrowed rather than made again so the fingerprint comes
/// from the same keystore view the caller goes on to load the signing key from.
/// `explicit_kid` names the key the caller asked for, and is the same value the
/// private key loader resolves against, so both settle on one key pair.
pub(crate) fn resolve_ssh_context_for_resolved_member(
    options: &CommonCommandOptions,
    resolved: &CommandMemberResolution,
    explicit_kid: Option<&str>,
) -> Result<SshSigningKeyResolution> {
    let (kid, fingerprint) = resolve_selected_key_ssh_fingerprint(
        &resolved.keystore_access,
        &resolved.member_handle,
        explicit_kid,
    )?;
    let ctx =
        resolve_ssh_context_for_fingerprint(options, &resolved.paths.global_config, &fingerprint)?;
    debug!("[SSH] Using SSH key: {}", ctx.fingerprint);
    Ok(SshSigningKeyResolution { kid, context: ctx })
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
                "SSH key for the selected key ({fingerprint}) not found in ssh-agent. \
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

/// Build the signing context for one fingerprint against a configuration the
/// command already read, so listing the candidates and building the context do
/// not open and parse the same file twice.
fn resolve_ssh_context_for_fingerprint(
    options: &CommonCommandOptions,
    config: &GlobalConfigSnapshot,
    fingerprint: &str,
) -> Result<SshSigningContextResolution> {
    let params = build_ssh_signing_params(options);
    let candidates = resolve_ssh_key_candidates_with_config(&params, config)?;
    let matched = find_ssh_candidate_by_fingerprint(&candidates, fingerprint)?;
    debug!("[SSH] matched selected key fingerprint={}", fingerprint);
    build_ssh_signing_context_with_config(&params, config, &matched.public_key)
}

/// Resolve the SSH fingerprint stored on the key this command will unlock.
///
/// The key is settled first — the one the caller named, or the member's active
/// one when it named none — and the fingerprint is then read from that very key
/// pair under one shared lock on the member. Choosing the SSH identity from the
/// active key while the caller named another one would hand a key protected
/// under one SSH identity to a context built for a different one, so a
/// `decrypt --kid K1` against a member whose active key is protected elsewhere
/// would fail to unlock a key that is perfectly valid.
fn resolve_selected_key_ssh_fingerprint(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    explicit_kid: Option<&str>,
) -> Result<(Kid, String)> {
    let (kid, private_key, _) = access.resolve_key_pair(member_handle, explicit_kid)?;
    let fingerprint = resolve_ssh_fingerprint_from_private_key(&private_key)?.to_string();
    Ok((kid, fingerprint))
}

fn format_determinism(status: &SshDeterminismStatus) -> &str {
    match status {
        SshDeterminismStatus::Verified => "verified",
        SshDeterminismStatus::Skipped => "skipped",
        SshDeterminismStatus::Failed { .. } => "failed",
    }
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
#[path = "../../../tests/unit/internal/app_context_ssh_selected_key_test.rs"]
mod app_context_ssh_selected_key_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_ssh_match_test.rs"]
mod feature_context_ssh_match_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_ssh_test.rs"]
mod feature_context_ssh_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_verify_public_key_attestation_test.rs"]
mod feature_verify_public_key_attestation_test;
