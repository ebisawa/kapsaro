// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::context::ssh::determinism::{probe_determinism, validate_ssh_key_type};
use crate::feature::context::ssh::params::{SshSigningContext, SshSigningParams};
use crate::feature::context::ssh::resolution::{
    resolve_backend_key_descriptor, resolve_signing_method, resolve_ssh_commands,
};
use crate::io::ssh::backend::build_backend;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::Result;

pub(crate) fn build_ssh_signing_context(
    params: &SshSigningParams,
    selected_pubkey: &str,
) -> Result<SshSigningContext> {
    let base_dir = params.base_dir.as_deref();
    let signing_method = resolve_signing_method(params, base_dir)?;
    let commands = resolve_ssh_commands(base_dir)?;

    validate_ssh_key_type(selected_pubkey)?;
    let fingerprint = build_sha256_fingerprint(selected_pubkey)?;
    let key_descriptor = resolve_backend_key_descriptor(signing_method, &params.ssh_key, base_dir)?;

    let ssh_keygen = Box::new(DefaultSshKeygen::new(commands.ssh_keygen_path));
    let backend = build_backend(signing_method, ssh_keygen, key_descriptor)?;
    let determinism = probe_determinism(params, backend.as_ref(), selected_pubkey)?;

    Ok(SshSigningContext {
        public_key: selected_pubkey.to_string(),
        fingerprint,
        backend,
        determinism,
    })
}
