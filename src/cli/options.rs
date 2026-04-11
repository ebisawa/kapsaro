// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::config::types::SshSigner;

/// Common options shared across all commands
#[derive(Debug, Clone, Args)]
pub struct CommonOptions {
    /// Base directory for secretenv
    #[arg(long)]
    pub home: Option<PathBuf>,

    /// SSH identity file (private key path)
    #[arg(long = "ssh-identity", short = 'i')]
    pub identity: Option<PathBuf>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,

    /// Quiet mode (suppress non-error output)
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Use ssh-agent for SSH signing
    #[arg(long, conflicts_with = "ssh_keygen")]
    pub ssh_agent: bool,

    /// Use ssh-keygen for SSH signing
    #[arg(long, conflicts_with = "ssh_agent")]
    pub ssh_keygen: bool,

    /// Verbose output
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Workspace root directory
    #[arg(long, short = 'w')]
    pub workspace: Option<PathBuf>,
}

impl CommonOptions {
    /// Resolve SSH signing method from --ssh-agent / --ssh-keygen flags
    pub fn ssh_signer(&self) -> Option<SshSigner> {
        if self.ssh_agent {
            Some(SshSigner::SshAgent)
        } else if self.ssh_keygen {
            Some(SshSigner::SshKeygen)
        } else {
            None
        }
    }
}

impl From<&CommonOptions> for CommonCommandOptions {
    fn from(value: &CommonOptions) -> Self {
        Self {
            home: value.home.clone(),
            identity: value.identity.clone(),
            verbose: value.verbose,
            workspace: value.workspace.clone(),
            ssh_signer: value.ssh_signer(),
        }
    }
}
