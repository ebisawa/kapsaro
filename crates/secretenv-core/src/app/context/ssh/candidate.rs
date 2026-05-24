// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH public key candidate resolution for app command contexts.

use super::resolution::{build_not_found_error, resolve_signing_method, resolve_ssh_commands};
use super::SshSigningParams;
use crate::config::resolution::ssh_key::{
    resolve_ssh_key_candidate, resolve_ssh_key_descriptor, SshKeySource,
};
use crate::config::types::SshSigningMethod;
use crate::io::ssh::external::add::DefaultSshAdd;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::external::pubkey::{
    load_ed25519_keys_from_agent, load_ssh_key_candidate_from_file, SshKeyCandidate,
};
use crate::io::ssh::protocol::SshKeyDescriptor;
use crate::Result;

pub(super) fn resolve_ssh_key_candidates(
    params: &SshSigningParams,
) -> Result<Vec<SshKeyCandidate>> {
    let base_dir = params.base_dir.as_deref();
    let signing_method = resolve_signing_method(params, base_dir)?;
    let commands = resolve_ssh_commands(base_dir)?;
    let ssh_keygen = DefaultSshKeygen::new(commands.ssh_keygen_path);
    let ssh_add = DefaultSshAdd::new(commands.ssh_add_path);

    match signing_method {
        SshSigningMethod::SshKeygen => resolve_file_candidates(params, &ssh_keygen),
        SshSigningMethod::SshAgent => resolve_agent_candidates(params, &ssh_keygen, &ssh_add),
    }
}

fn resolve_file_candidates(
    params: &SshSigningParams,
    ssh_keygen: &DefaultSshKeygen,
) -> Result<Vec<SshKeyCandidate>> {
    let descriptor =
        resolve_ssh_key_descriptor(params.ssh_key.clone(), params.base_dir.as_deref())?;
    let candidate = load_ssh_key_candidate_from_file(ssh_keygen, &descriptor)?;
    Ok(vec![candidate])
}

fn resolve_agent_candidates(
    params: &SshSigningParams,
    ssh_keygen: &DefaultSshKeygen,
    ssh_add: &DefaultSshAdd,
) -> Result<Vec<SshKeyCandidate>> {
    let resolved = resolve_ssh_key_candidate(params.ssh_key.clone(), params.base_dir.as_deref())?;
    let is_explicit = resolved.source != SshKeySource::Default;

    if !is_explicit {
        return load_ed25519_keys_from_agent(ssh_add);
    }
    if !resolved.exists {
        return Err(build_not_found_error(&resolved));
    }

    let descriptor = SshKeyDescriptor::from_path(resolved.path);
    let candidate = load_ssh_key_candidate_from_file(ssh_keygen, &descriptor)?;
    Ok(vec![candidate])
}
