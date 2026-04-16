// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::context::ssh::params::SshSigningParams;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::protocol::constants as ssh;
use crate::model::identifiers::context::SSH_DETERMINISM_CHECK_MESSAGE;
use crate::model::ssh::SshDeterminismStatus;
use crate::{Error, Result};
use tracing::debug;

const NON_DETERMINISTIC_SIGNATURE_MESSAGE: &str =
    "Non-deterministic signature detected: same input produced different signatures";

pub(crate) fn probe_determinism(
    params: &SshSigningParams,
    backend: &dyn SignatureBackend,
    ssh_pub: &str,
) -> Result<SshDeterminismStatus> {
    if !params.check_determinism {
        return Ok(SshDeterminismStatus::Skipped);
    }

    let determinism = match backend.check_sshsig_determinism(
        ssh::KEY_PROTECTION_NAMESPACE,
        ssh_pub,
        SSH_DETERMINISM_CHECK_MESSAGE,
    ) {
        Ok(()) => Ok(SshDeterminismStatus::Verified),
        Err(error) if is_non_deterministic_signature_error(&error) => {
            Ok(SshDeterminismStatus::Failed {
                message:
                    "SSH signature determinism check failed. This SSH key cannot be used for key generation.".to_string(),
            })
        }
        Err(error) => Err(error),
    };

    if params.verbose {
        match &determinism {
            Ok(status) => debug!("[SSH] Determinism check: {}", status.is_verified()),
            Err(error) => debug!("[SSH] Determinism check failed: {}", error),
        }
    }

    determinism
}

pub(crate) fn validate_ssh_key_type(ssh_pub: &str) -> Result<()> {
    let key_type = ssh_pub.split_whitespace().next().unwrap_or("unknown");
    if key_type != ssh::KEY_TYPE_ED25519 {
        return Err(Error::InvalidArgument {
            message: format!("Only Ed25519 SSH keys are supported. Got: {}", key_type),
        });
    }
    Ok(())
}

fn is_non_deterministic_signature_error(error: &Error) -> bool {
    error
        .to_string()
        .contains(NON_DETERMINISTIC_SIGNATURE_MESSAGE)
}
