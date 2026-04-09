// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::resolution::common::{resolve_ssh_add_path, resolve_ssh_keygen_path};
use crate::config::resolution::ssh_key::{
    build_ssh_key_not_found_error, resolve_ssh_key_descriptor, ResolvedSshKey,
};
use crate::config::resolution::ssh_signer::{resolve_ssh_signer, resolve_ssh_signer_config};
use crate::config::types::SshSigner;
use crate::feature::context::ssh::params::{ResolvedSshCommands, SshSigningParams};
use crate::io::ssh::protocol::SshKeyDescriptor;
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use tracing::debug;

pub(crate) fn resolve_signing_method(
    params: &SshSigningParams,
    base_dir: Option<&Path>,
) -> Result<SshSigner> {
    let signing_method_config = resolve_ssh_signer_config(params.signing_method, base_dir)?;
    let signing_method = resolve_ssh_signer(signing_method_config);

    if params.verbose {
        debug!("[SSH] Signing method: {}", signing_method);
    }

    Ok(signing_method)
}

pub(crate) fn resolve_ssh_commands(base_dir: Option<&Path>) -> Result<ResolvedSshCommands> {
    Ok(ResolvedSshCommands {
        ssh_keygen_path: resolve_ssh_keygen_path(base_dir)?,
        ssh_add_path: resolve_ssh_add_path(base_dir)?,
    })
}

pub(crate) fn resolve_backend_key_descriptor(
    signing_method: SshSigner,
    ssh_key: &Option<PathBuf>,
    base_dir: Option<&Path>,
) -> Result<Option<SshKeyDescriptor>> {
    match signing_method {
        SshSigner::SshKeygen => resolve_ssh_key_descriptor(ssh_key.clone(), base_dir).map(Some),
        SshSigner::SshAgent => match ssh_key {
            Some(path) => Ok(Some(SshKeyDescriptor::from_path(path.clone()))),
            None => Ok(None),
        },
    }
}

pub(crate) fn build_not_found_error(candidate: &ResolvedSshKey) -> Error {
    build_ssh_key_not_found_error(candidate)
}
