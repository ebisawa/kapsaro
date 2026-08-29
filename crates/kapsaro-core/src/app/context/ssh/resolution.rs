// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH signing method and command resolution for app command contexts.

use super::SshSigningParams;
use crate::config::resolution::common::{resolve_ssh_add_path, resolve_ssh_keygen_path};
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::config::resolution::ssh_key::{
    build_ssh_key_not_found_error, resolve_ssh_key_descriptor, SshKeyResolution,
};
use crate::config::resolution::ssh_signing_method::{
    resolve_ssh_signing_method, resolve_ssh_signing_method_config,
};
use crate::config::types::SshSigningMethod;
use crate::io::ssh::protocol::SshKeyDescriptor;
use crate::{Error, Result};
use std::path::PathBuf;
use tracing::debug;

pub(super) struct SshCommandResolution {
    pub ssh_keygen_path: String,
    pub ssh_add_path: String,
}

pub(super) fn resolve_signing_method(
    params: &SshSigningParams,
    config: &GlobalConfigSnapshot,
) -> Result<SshSigningMethod> {
    let signing_method_config = resolve_ssh_signing_method_config(params.signing_method, config)?;
    let signing_method = resolve_ssh_signing_method(signing_method_config);

    debug!("[SSH] Signing method: {}", signing_method);

    Ok(signing_method)
}

pub(super) fn resolve_ssh_commands(config: &GlobalConfigSnapshot) -> Result<SshCommandResolution> {
    Ok(SshCommandResolution {
        ssh_keygen_path: resolve_ssh_keygen_path(config)?,
        ssh_add_path: resolve_ssh_add_path(config)?,
    })
}

pub(super) fn resolve_backend_key_descriptor(
    signing_method: SshSigningMethod,
    ssh_key: &Option<PathBuf>,
    config: &GlobalConfigSnapshot,
) -> Result<Option<SshKeyDescriptor>> {
    match signing_method {
        SshSigningMethod::SshKeygen => {
            resolve_ssh_key_descriptor(ssh_key.clone(), config).map(Some)
        }
        SshSigningMethod::SshAgent => match ssh_key {
            Some(path) => Ok(Some(SshKeyDescriptor::from_path(path.clone()))),
            None => Ok(None),
        },
    }
}

pub(super) fn build_not_found_error(candidate: &SshKeyResolution) -> Error {
    build_ssh_key_not_found_error(candidate)
}
